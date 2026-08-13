#!/usr/bin/env bash
#
# home-base installer.
#
# Keeps an existing nftables set in sync with an IP whitelist read from an
# external, admin-editable source (a GitHub gist or any URL that answers a
# plain GET with whitelist text), so a VPN server's access whitelist can be
# updated from wherever you're traveling without SSHing in by hand.
#
# home-base does NOT create or own a firewall ruleset -- the target
# nftables set has to already exist (as part of whatever firewall setup
# your VPN server already has). This only manages that one set's element
# membership.
#
# Safe to re-run: every step either checks before creating, or overwrites a
# file this script owns outright.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must be run as root (sudo ./install.sh)"

# ---------------------------------------------------------------------------
# 1. Config
# ---------------------------------------------------------------------------
if [[ -f "$SCRIPT_DIR/homebase.conf" ]]; then
    log "loading homebase.conf"
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/homebase.conf"
else
    log "homebase.conf not found -- copying homebase.conf.example, edit it and re-run to actually sync anything"
    cp "$SCRIPT_DIR/homebase.conf.example" "$SCRIPT_DIR/homebase.conf"
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/homebase.conf"
fi

for v in NFT_FAMILY NFT_TABLE NFT_SET POLL_INTERVAL_SECONDS SOURCE_TYPE \
         DASHBOARD_PORT DASHBOARD_LAN_IP OPENVPN_PORT OPENVPN_PROTO \
         OPENVPN_SUBNET OPENVPN_SUBNET_MASK LAN_SUBNET EASYRSA_REQ_CN; do
    [[ -n "${!v:-}" ]] || die "config variable $v is not set"
done

case "$SOURCE_TYPE" in
    github_gist)
        [[ -n "${GIST_ID:-}" && -n "${GIST_TOKEN:-}" ]] || \
            warn "SOURCE_TYPE=github_gist but GIST_ID/GIST_TOKEN aren't both set yet -- configure a source from the dashboard, or edit homebase.conf and restart the service"
        ;;
    raw_url)
        [[ -n "${SOURCE_URL:-}" ]] || \
            warn "SOURCE_TYPE=raw_url but SOURCE_URL isn't set yet -- configure a source from the dashboard, or edit homebase.conf and restart the service"
        ;;
    *)
        die "SOURCE_TYPE must be 'github_gist' or 'raw_url', got '$SOURCE_TYPE'"
        ;;
esac

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
render() {
    # render <template> <outfile> KEY=value [KEY=value ...]
    local template="$1" outfile="$2"
    shift 2
    local content
    content="$(cat "$template")"
    local kv key val
    for kv in "$@"; do
        key="${kv%%=*}"
        val="${kv#*=}"
        content="${content//__${key}__/$val}"
    done
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$content" > "$tmp"
    install -m 0644 "$tmp" "$outfile"
    rm -f "$tmp"
}

# ---------------------------------------------------------------------------
# 2. Packages
# ---------------------------------------------------------------------------
log "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y python3-flask openvpn easy-rsa

# ---------------------------------------------------------------------------
# 3. OpenVPN + the nftables scaffolding around it -- adopt if it already
#    exists, provision from scratch on a clean box. These two are handled
#    as one bundle: a whitelist-gated set with nothing to gate is pointless,
#    and an OpenVPN server with no whitelist gating it is the opposite of
#    what this project is for.
# ---------------------------------------------------------------------------
OPENVPN_SERVER_EXISTS=0
[[ -f /etc/openvpn/server/server.conf ]] && OPENVPN_SERVER_EXISTS=1
NFT_SET_EXISTS=0
nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET" >/dev/null 2>&1 && NFT_SET_EXISTS=1

if [[ "$OPENVPN_SERVER_EXISTS" -eq 1 && "$NFT_SET_EXISTS" -eq 1 ]]; then
    log "existing OpenVPN server and $NFT_FAMILY $NFT_TABLE $NFT_SET both found -- adopting, not touching either"
elif [[ "$OPENVPN_SERVER_EXISTS" -eq 1 || "$NFT_SET_EXISTS" -eq 1 ]]; then
    die "found one of {OpenVPN server, nftables set $NFT_SET} but not the other --
      that's an inconsistent state this installer won't guess how to reconcile.
      OpenVPN server present: $OPENVPN_SERVER_EXISTS ; nftables set present: $NFT_SET_EXISTS
      Sort out the missing half by hand, then re-run."
else
    log "no existing OpenVPN server found -- provisioning one from scratch"

    # easyrsa init-pki silently wipes an existing PKI directory in batch
    # mode, no confirmation. If a previous provisioning attempt got partway
    # through and died (server.conf not written yet, so we're here again),
    # blindly re-running init-pki would destroy whatever CA/certs it already
    # built rather than resuming or failing loudly. Refuse instead.
    if [[ -d /etc/openvpn/easy-rsa/pki ]]; then
        die "/etc/openvpn/easy-rsa/pki already exists but /etc/openvpn/server/server.conf
      doesn't -- looks like a previous provisioning attempt got partway through.
      Not proceeding: easyrsa would silently wipe that PKI directory. Inspect it, back up
      anything worth keeping (especially pki/private/ca.key), then remove
      /etc/openvpn/easy-rsa/pki by hand and re-run this installer."
    fi

    WAN_IF="$(ip route show default | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')"
    [[ -n "$WAN_IF" ]] || die "could not detect a default-route (internet-facing) interface to bind OpenVPN/nftables to"
    log "  internet-facing interface: $WAN_IF"

    LAN_NETWORK="${LAN_SUBNET%/*}"
    LAN_NETMASK="$(python3 -c "import ipaddress; print(ipaddress.IPv4Network('$LAN_SUBNET').netmask)")"
    OPENVPN_SUBNET_CIDR="$(python3 -c "
import ipaddress
print(ipaddress.IPv4Network(('$OPENVPN_SUBNET', '$OPENVPN_SUBNET_MASK')))
")"

    log "  setting up easy-rsa PKI at /etc/openvpn/easy-rsa"
    mkdir -p /etc/openvpn/easy-rsa
    ln -sf /usr/share/easy-rsa/easyrsa /etc/openvpn/easy-rsa/easyrsa
    ln -sf /usr/share/easy-rsa/openssl-easyrsa.cnf /etc/openvpn/easy-rsa/openssl-easyrsa.cnf
    ln -sf /usr/share/easy-rsa/x509-types /etc/openvpn/easy-rsa/x509-types
    cat > /etc/openvpn/easy-rsa/vars <<EOF
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE secp384r1
set_var EASYRSA_BATCH yes
set_var EASYRSA_REQ_COUNTRY "US"
set_var EASYRSA_REQ_PROVINCE "State"
set_var EASYRSA_REQ_CITY "City"
set_var EASYRSA_REQ_ORG "home-base"
set_var EASYRSA_REQ_EMAIL "admin@home-base.local"
set_var EASYRSA_REQ_OU "home-base"
set_var EASYRSA_REQ_CN "$EASYRSA_REQ_CN"
set_var EASYRSA_CERT_EXPIRE 3650
EOF

    (
        cd /etc/openvpn/easy-rsa
        ./easyrsa init-pki
        EASYRSA_REQ_CN="$EASYRSA_REQ_CN" ./easyrsa build-ca nopass
        EASYRSA_REQ_CN=server ./easyrsa build-server-full server nopass
        ./easyrsa gen-crl
    )

    log "  generating tls-crypt key"
    openvpn --genkey secret /etc/openvpn/easy-rsa/pki/tc.key

    log "  installing server config to /etc/openvpn/server/"
    mkdir -p /etc/openvpn/server
    for f in ca.crt issued/server.crt private/server.key crl.pem; do
        install -m 0600 "/etc/openvpn/easy-rsa/pki/$f" "/etc/openvpn/server/$(basename "$f")"
    done
    install -m 0600 /etc/openvpn/easy-rsa/pki/tc.key /etc/openvpn/server/tc.key
    render "$SCRIPT_DIR/templates/openvpn-server.conf.tmpl" /etc/openvpn/server/server.conf \
        "OPENVPN_PORT=$OPENVPN_PORT" \
        "OPENVPN_PROTO=$OPENVPN_PROTO" \
        "OPENVPN_SUBNET=$OPENVPN_SUBNET" \
        "OPENVPN_SUBNET_MASK=$OPENVPN_SUBNET_MASK" \
        "LAN_NETWORK=$LAN_NETWORK" \
        "LAN_NETMASK=$LAN_NETMASK"
    mkdir -p /var/log/openvpn

    log "  installing nftables scaffolding (table $NFT_FAMILY $NFT_TABLE, set $NFT_SET)"
    TMP_NFT="$(mktemp)"
    content="$(cat "$SCRIPT_DIR/templates/nftables-vpn.conf.tmpl")"
    for kv in "NFT_FAMILY=$NFT_FAMILY" "NFT_TABLE=$NFT_TABLE" "NFT_SET=$NFT_SET" \
              "WAN_IF=$WAN_IF" "OPENVPN_PROTO=$OPENVPN_PROTO" "OPENVPN_PORT=$OPENVPN_PORT" \
              "OPENVPN_SUBNET_CIDR=$OPENVPN_SUBNET_CIDR"; do
        key="${kv%%=*}"; val="${kv#*=}"
        content="${content//__${key}__/$val}"
    done
    printf '%s\n' "$content" > "$TMP_NFT"
    nft -f "$TMP_NFT"
    rm -f "$TMP_NFT"
    systemctl enable nftables >/dev/null 2>&1 || true

    systemctl daemon-reload
    systemctl enable openvpn-server@server >/dev/null
    systemctl restart openvpn-server@server
fi

# ---------------------------------------------------------------------------
# 4. DDNS (No-IP / noip-duc) -- adopt if present, otherwise this is
#    supplementary: warn and move on rather than block the rest of the
#    install. noip-duc isn't in any apt repo (a direct .deb download from
#    No-IP with no stable scriptable URL), so a clean box needs it installed
#    by hand first.
# ---------------------------------------------------------------------------
if command -v noip-duc >/dev/null 2>&1 && [[ -s /etc/default/noip-duc ]]; then
    log "existing noip-duc install found and configured -- adopting, not touching its config"
    NOIP_ADOPTED_HOSTNAMES="$(grep -oP '^NOIP_HOSTNAMES=\K.*' /etc/default/noip-duc || true)"
    [[ -n "$NOIP_ADOPTED_HOSTNAMES" ]] && log "  DDNS hostname(s): $NOIP_ADOPTED_HOSTNAMES"
elif command -v noip-duc >/dev/null 2>&1 && [[ -n "${NOIP_USERNAME:-}" && -n "${NOIP_PASSWORD:-}" && -n "${NOIP_HOSTNAMES:-}" ]]; then
    log "noip-duc is installed but unconfigured -- configuring from homebase.conf"
    cat > /etc/default/noip-duc <<EOF
NOIP_USERNAME=$NOIP_USERNAME
NOIP_PASSWORD=$NOIP_PASSWORD
NOIP_HOSTNAMES=$NOIP_HOSTNAMES
NOIP_CHECK_INTERVAL=5m
NOIP_LOG_LEVEL=info
EOF
    chmod 0600 /etc/default/noip-duc
    systemctl enable --now noip-duc >/dev/null 2>&1 || true
elif command -v noip-duc >/dev/null 2>&1; then
    warn "noip-duc is installed but not configured, and NOIP_USERNAME/NOIP_PASSWORD/NOIP_HOSTNAMES
      aren't all set in homebase.conf -- set them and re-run to configure it."
elif [[ -n "${NOIP_USERNAME:-}" && -n "${NOIP_PASSWORD:-}" && -n "${NOIP_HOSTNAMES:-}" ]]; then
    warn "noip-duc isn't installed and isn't in any apt repo -- download the .deb for this
      architecture from https://www.noip.com/download, install it (dpkg -i), then re-run
      this installer to have it configured from NOIP_USERNAME/NOIP_PASSWORD/NOIP_HOSTNAMES
      in homebase.conf."
else
    log "noip-duc not found and no NOIP_* credentials set in homebase.conf -- skipping DDNS setup"
fi

# Auto-fill VPN_REMOTE_HOST (used when generating client .ovpn bundles) from
# whichever DDNS hostname was just discovered or configured, if it's blank.
DISCOVERED_HOSTNAME="${NOIP_ADOPTED_HOSTNAMES:-${NOIP_HOSTNAMES:-}}"
DISCOVERED_HOSTNAME="${DISCOVERED_HOSTNAME%%,*}"
if [[ -z "${VPN_REMOTE_HOST:-}" && -n "$DISCOVERED_HOSTNAME" ]]; then
    log "setting VPN_REMOTE_HOST=$DISCOVERED_HOSTNAME in homebase.conf (was blank)"
    if grep -q '^VPN_REMOTE_HOST=' "$SCRIPT_DIR/homebase.conf"; then
        sed -i "s/^VPN_REMOTE_HOST=.*/VPN_REMOTE_HOST=\"${DISCOVERED_HOSTNAME}\"/" "$SCRIPT_DIR/homebase.conf"
    else
        echo "VPN_REMOTE_HOST=\"${DISCOVERED_HOSTNAME}\"" >> "$SCRIPT_DIR/homebase.conf"
    fi
    VPN_REMOTE_HOST="$DISCOVERED_HOSTNAME"
fi

# ---------------------------------------------------------------------------
# 5. Deploy
# ---------------------------------------------------------------------------
log "installing web app to /opt/home-base"
mkdir -p /opt/home-base
rm -rf /opt/home-base/webapp
cp -a "$SCRIPT_DIR/webapp" /opt/home-base/webapp
chown -R root:root /opt/home-base/webapp

mkdir -p /etc/home-base
if [[ -f /etc/home-base/homebase.conf ]]; then
    log "config already deployed at /etc/home-base/homebase.conf -- leaving it as-is"
    log "  (it may have been edited since via the dashboard's source-config form; edit"
    log "   /etc/home-base/homebase.conf directly, or the dashboard, not this repo's copy)"
else
    log "installing config to /etc/home-base/homebase.conf"
    install -m 0600 "$SCRIPT_DIR/homebase.conf" /etc/home-base/homebase.conf
fi

log "installing systemd service"
install -m 0644 "$SCRIPT_DIR/templates/home-base.service.tmpl" /etc/systemd/system/home-base.service
systemctl daemon-reload
systemctl enable home-base >/dev/null
systemctl restart home-base

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
cat <<EOF

==================================================================
home-base setup complete.

  OpenVPN        : $([[ "$OPENVPN_SERVER_EXISTS" -eq 1 ]] && echo "existing server adopted" || echo "provisioned fresh on $OPENVPN_PORT/$OPENVPN_PROTO")
  Syncing        : $NFT_FAMILY $NFT_TABLE $NFT_SET, every ${POLL_INTERVAL_SECONDS}s
  Source         : $SOURCE_TYPE
  Dashboard      : http://127.0.0.1:${DASHBOARD_PORT} or http://${DASHBOARD_LAN_IP}:${DASHBOARD_PORT}
                    (reachable only from those addresses, same posture as pi5-router's dashboard)

Edit /etc/home-base/homebase.conf and \`systemctl restart home-base\` to change source
settings, the poll interval, or which nftables set gets synced. Generate client certs
from the dashboard's Clients card.
==================================================================
EOF
