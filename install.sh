#!/usr/bin/env bash
#
# home-base installer.
#
# Keeps an nftables set in sync with an IP whitelist read from an external,
# admin-editable source (a GitHub gist or any URL that answers a plain GET
# with whitelist text), so a VPN server's access whitelist can be updated
# from wherever you're traveling without SSHing in by hand. Runs OpenVPN,
# WireGuard, or both (ENABLE_OPENVPN / ENABLE_WIREGUARD in homebase.conf) --
# whichever backend(s) are enabled share the same whitelist-gated set.
#
# home-base does NOT create or own a general firewall ruleset -- if the
# nftables set/base chains already exist (as part of whatever firewall setup
# the box already has), they're adopted as-is. This only manages that one
# set's element membership, plus the specific accept rules each enabled VPN
# backend needs, added additively without touching anything else already
# on the box.
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
         DASHBOARD_PORT DASHBOARD_ALLOWED_SUBNET OPENVPN_PORT OPENVPN_PROTO \
         OPENVPN_SUBNET OPENVPN_SUBNET_MASK LAN_SUBNET EASYRSA_REQ_CN; do
    [[ -n "${!v:-}" ]] || die "config variable $v is not set"
done

# Both default on/off exactly as they always implicitly were before these
# existed (OpenVPN on, nothing else) -- not in the required-var loop above,
# so a homebase.conf from before WireGuard support keeps working unchanged.
ENABLE_OPENVPN="${ENABLE_OPENVPN:-true}"
ENABLE_WIREGUARD="${ENABLE_WIREGUARD:-false}"
WIREGUARD_PORT="${WIREGUARD_PORT:-51820}"
WIREGUARD_SUBNET="${WIREGUARD_SUBNET:-10.9.0.0}"
WIREGUARD_SUBNET_MASK="${WIREGUARD_SUBNET_MASK:-255.255.255.0}"

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
PACKAGES=(python3-flask)
[[ "$ENABLE_OPENVPN" == "true" ]] && PACKAGES+=(openvpn easy-rsa)
[[ "$ENABLE_WIREGUARD" == "true" ]] && PACKAGES+=(wireguard)
apt-get install -y "${PACKAGES[@]}"

WAN_IF="$(ip route show default | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')"
[[ -n "$WAN_IF" ]] || die "could not detect a default-route (internet-facing) interface"
log "internet-facing interface: $WAN_IF"

# ---------------------------------------------------------------------------
# IP forwarding -- required for the kernel to route packets between
# interfaces at all (tun0/wg0 <-> WAN_IF), independent of and in addition to
# the nftables forward-chain rules below. Without this, a client can
# complete a handshake/connect and reach the box itself fine, but anything
# meant to transit through it (full-tunnel internet, or a route to the LAN)
# silently goes nowhere -- nftables' forward hook is never even consulted
# if the kernel isn't forwarding at all. OpenVPN's own config here only
# ever pushes a specific LAN route, never a full-tunnel redirect-gateway,
# which is how this went unnoticed until a WireGuard peer using
# AllowedIPs=0.0.0.0/0 (full tunnel) actually exercised it.
# ---------------------------------------------------------------------------
if [[ "$ENABLE_OPENVPN" == "true" || "$ENABLE_WIREGUARD" == "true" ]]; then
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        log "enabled IP forwarding (was off)"
    else
        log "IP forwarding already enabled"
    fi
    SYSCTL_FORWARD_FILE=/etc/sysctl.d/99-home-base-forwarding.conf
    if [[ ! -f "$SYSCTL_FORWARD_FILE" ]] || ! grep -q '^net.ipv4.ip_forward=1$' "$SYSCTL_FORWARD_FILE"; then
        echo 'net.ipv4.ip_forward=1' > "$SYSCTL_FORWARD_FILE"
        log "  persisted to $SYSCTL_FORWARD_FILE (survives reboot)"
    fi
fi

# Helpers for the idempotent rule-adding steps below (3b/3d/3f) -- checks
# before adding, and tracks whether anything actually changed so the
# `/etc/nftables.conf` persist step only runs once at the end, not once per
# rule.
NFT_RULESET_CHANGED=0
ensure_nft_rule() {
    # ensure_nft_rule <chain> <grep-pattern> <rule...>
    local chain="$1" pattern="$2"
    shift 2
    if nft list chain "$NFT_FAMILY" "$NFT_TABLE" "$chain" 2>/dev/null | grep -q "$pattern"; then
        log "  $chain rule already present ($pattern) -- leaving it as-is"
        return 0
    fi
    nft add rule "$NFT_FAMILY" "$NFT_TABLE" "$chain" "$@"
    log "  added to $chain: $*"
    NFT_RULESET_CHANGED=1
}
ensure_nat_rule() {
    # ensure_nat_rule <grep-pattern> <rule...>
    local pattern="$1"
    shift
    if nft list chain ip nat postrouting 2>/dev/null | grep -q "$pattern"; then
        log "  nat postrouting rule already present ($pattern) -- leaving it as-is"
        return 0
    fi
    nft add rule ip nat postrouting "$@"
    log "  added to nat postrouting: $*"
    NFT_RULESET_CHANGED=1
}

# ---------------------------------------------------------------------------
# 3. Base nftables skeleton (table/set/chains) -- shared by whichever VPN
#    backend(s) are enabled below. Adopt if it already exists, provision
#    fresh otherwise. Deliberately independent of ENABLE_OPENVPN/
#    ENABLE_WIREGUARD: NFT_SET is the shared whitelist target regardless of
#    which VPN(s) actually use it, so its existence no longer implies "and
#    OpenVPN must exist too" the way it did when this only supported one
#    backend.
# ---------------------------------------------------------------------------
NFT_SET_EXISTS=0
nft list set "$NFT_FAMILY" "$NFT_TABLE" "$NFT_SET" >/dev/null 2>&1 && NFT_SET_EXISTS=1

if [[ "$NFT_SET_EXISTS" -eq 1 ]]; then
    log "existing $NFT_FAMILY $NFT_TABLE $NFT_SET found -- adopting, not touching the base ruleset"
else
    log "no existing $NFT_FAMILY $NFT_TABLE $NFT_SET -- provisioning the base nftables skeleton"
    TMP_NFT="$(mktemp)"
    content="$(cat "$SCRIPT_DIR/templates/nftables-vpn.conf.tmpl")"
    for kv in "NFT_FAMILY=$NFT_FAMILY" "NFT_TABLE=$NFT_TABLE" "NFT_SET=$NFT_SET"; do
        key="${kv%%=*}"; val="${kv#*=}"
        content="${content//__${key}__/$val}"
    done
    printf '%s\n' "$content" > "$TMP_NFT"
    nft -f "$TMP_NFT"
    rm -f "$TMP_NFT"
    systemctl enable nftables >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 3a. OpenVPN -- adopt if it already exists, provision from scratch
#     otherwise. No nftables rules here anymore (see 3b) -- this step is
#     purely the PKI/server-config/systemd side.
# ---------------------------------------------------------------------------
OPENVPN_SERVER_EXISTS=0
[[ -f /etc/openvpn/server/server.conf ]] && OPENVPN_SERVER_EXISTS=1

if [[ "$ENABLE_OPENVPN" != "true" ]]; then
    log "ENABLE_OPENVPN=false -- skipping OpenVPN"
elif [[ "$OPENVPN_SERVER_EXISTS" -eq 1 ]]; then
    log "existing OpenVPN server found -- adopting, not touching it"
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

    LAN_NETWORK="${LAN_SUBNET%/*}"
    LAN_NETMASK="$(python3 -c "import ipaddress; print(ipaddress.IPv4Network('$LAN_SUBNET').netmask)")"

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

    systemctl daemon-reload
    systemctl enable openvpn-server@server >/dev/null
    systemctl restart openvpn-server@server
fi

# ---------------------------------------------------------------------------
# 3b. OpenVPN nftables rules -- additive and idempotent, runs every time
#     (fresh provision or adopted box alike), gated only by ENABLE_OPENVPN.
#     This, not step 3a, is what makes OpenVPN's whitelist gating apply
#     whether OpenVPN itself was just provisioned above or was already
#     sitting there from before this installer supported multiple backends.
# ---------------------------------------------------------------------------
if [[ "$ENABLE_OPENVPN" == "true" ]]; then
    log "ensuring nftables rules for OpenVPN"
    OPENVPN_SUBNET_CIDR="$(python3 -c "
import ipaddress
print(ipaddress.IPv4Network(('$OPENVPN_SUBNET', '$OPENVPN_SUBNET_MASK')))
")"
    ensure_nft_rule input "dport $OPENVPN_PORT .*ip saddr @$NFT_SET" \
        iifname "$WAN_IF" "$OPENVPN_PROTO" dport "$OPENVPN_PORT" ip saddr "@$NFT_SET" accept
    ensure_nft_rule forward "iifname \"tun0\" oifname \"$WAN_IF\"" \
        iifname tun0 oifname "$WAN_IF" accept
    ensure_nat_rule "ip saddr $OPENVPN_SUBNET_CIDR" \
        ip saddr "$OPENVPN_SUBNET_CIDR" oifname "$WAN_IF" masquerade
fi

# ---------------------------------------------------------------------------
# 3c. WireGuard -- adopt if it already exists, provision from scratch
#     otherwise. No CA/PKI (unlike OpenVPN) -- just a server keypair and an
#     [Interface] block; peers are added later from the dashboard.
# ---------------------------------------------------------------------------
WIREGUARD_EXISTS=0
[[ -f /etc/wireguard/wg0.conf ]] && WIREGUARD_EXISTS=1

if [[ "$ENABLE_WIREGUARD" != "true" ]]; then
    log "ENABLE_WIREGUARD=false -- skipping WireGuard"
elif [[ "$WIREGUARD_EXISTS" -eq 1 ]]; then
    log "existing WireGuard config found -- adopting, not touching it"
else
    log "no existing WireGuard config found -- provisioning one from scratch"
    read -r WIREGUARD_SERVER_ADDR WIREGUARD_PREFIXLEN <<<"$(python3 -c "
import ipaddress
net = ipaddress.IPv4Network(('$WIREGUARD_SUBNET', '$WIREGUARD_SUBNET_MASK'))
print(next(net.hosts()), net.prefixlen)
")"

    install -d -m 0700 /etc/wireguard
    umask 077
    wg genkey > /etc/wireguard/server_private.key
    wg pubkey < /etc/wireguard/server_private.key > /etc/wireguard/server_public.key
    umask 022
    chmod 600 /etc/wireguard/server_private.key

    render "$SCRIPT_DIR/templates/wireguard-server.conf.tmpl" /etc/wireguard/wg0.conf \
        "WIREGUARD_SERVER_ADDR=$WIREGUARD_SERVER_ADDR" \
        "WIREGUARD_PREFIXLEN=$WIREGUARD_PREFIXLEN" \
        "WIREGUARD_PORT=$WIREGUARD_PORT" \
        "WIREGUARD_SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_private.key)"
    chmod 600 /etc/wireguard/wg0.conf

    systemctl enable --now wg-quick@wg0 >/dev/null
fi

# ---------------------------------------------------------------------------
# 3d. WireGuard nftables rules -- additive and idempotent, same pattern and
#     same reasoning as 3b.
# ---------------------------------------------------------------------------
if [[ "$ENABLE_WIREGUARD" == "true" ]]; then
    log "ensuring nftables rules for WireGuard"
    WIREGUARD_SUBNET_CIDR="$(python3 -c "
import ipaddress
print(ipaddress.IPv4Network(('$WIREGUARD_SUBNET', '$WIREGUARD_SUBNET_MASK')))
")"
    ensure_nft_rule input "dport $WIREGUARD_PORT .*ip saddr @$NFT_SET" \
        iifname "$WAN_IF" udp dport "$WIREGUARD_PORT" ip saddr "@$NFT_SET" accept
    ensure_nft_rule forward "iifname \"wg0\" oifname \"$WAN_IF\"" \
        iifname wg0 oifname "$WAN_IF" accept
    ensure_nat_rule "ip saddr $WIREGUARD_SUBNET_CIDR" \
        ip saddr "$WIREGUARD_SUBNET_CIDR" oifname "$WAN_IF" masquerade
fi

# ---------------------------------------------------------------------------
# 3e. Dashboard access rule -- runs every time regardless of which VPN
#     backend(s) are enabled, unlike 3b/3d above. The dashboard binds to
#     0.0.0.0 (see webapp/app.py); this rule is the only thing standing
#     between that and the open internet, so it isn't optional the way the
#     rest of this installer's "adopt, don't touch" posture is.
# ---------------------------------------------------------------------------
log "ensuring an nftables rule allows dashboard access from $DASHBOARD_ALLOWED_SUBNET"
ensure_nft_rule input "dport $DASHBOARD_PORT .*ip saddr $DASHBOARD_ALLOWED_SUBNET" \
    iifname "$WAN_IF" tcp dport "$DASHBOARD_PORT" ip saddr "$DASHBOARD_ALLOWED_SUBNET" accept

# ---------------------------------------------------------------------------
# 3f. Persist the live ruleset if 3b/3d/3e actually changed anything.
#     /etc/nftables.conf (loaded by nftables.service at boot) is a separate
#     file from the live ruleset `nft add` changes -- a snapshot here is
#     what makes any of the above survive a reboot.
# ---------------------------------------------------------------------------
if [[ "$NFT_RULESET_CHANGED" -eq 1 ]]; then
    { echo '#!/usr/sbin/nft -f'; echo 'flush ruleset'; nft list ruleset; } > /etc/nftables.conf
    log "persisted nftables ruleset to /etc/nftables.conf"
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

  OpenVPN        : $([[ "$ENABLE_OPENVPN" != "true" ]] && echo "disabled" || { [[ "$OPENVPN_SERVER_EXISTS" -eq 1 ]] && echo "existing server adopted" || echo "provisioned fresh on $OPENVPN_PORT/$OPENVPN_PROTO"; })
  WireGuard      : $([[ "$ENABLE_WIREGUARD" != "true" ]] && echo "disabled" || { [[ "$WIREGUARD_EXISTS" -eq 1 ]] && echo "existing config adopted" || echo "provisioned fresh on $WIREGUARD_PORT/udp"; })
  Syncing        : $NFT_FAMILY $NFT_TABLE $NFT_SET, every ${POLL_INTERVAL_SECONDS}s
  Source         : $SOURCE_TYPE
  Dashboard      : http://<this box's address>:${DASHBOARD_PORT}
                    (nftables restricts access to $DASHBOARD_ALLOWED_SUBNET)

Edit /etc/home-base/homebase.conf and \`systemctl restart home-base\` to change source
settings, the poll interval, or which nftables set gets synced. Generate OpenVPN
client certs from the dashboard's Client Certificates card, WireGuard peers from
its WireGuard Peers card.
==================================================================
EOF
