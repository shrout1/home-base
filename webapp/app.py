#!/usr/bin/env python3
# home-base: keeps an nftables set in sync with an IP whitelist read from an
# external, admin-editable source (a GitHub gist or any URL that hands back
# plain text), so a VPN server's access whitelist can be updated from
# wherever the admin is traveling without SSHing in by hand.
#
# Binds to 0.0.0.0:DASHBOARD_PORT -- access control is nftables' job, not
# the bind address (see the dashboard rule installer.sh adds: source-IP
# restricted to LAN_SUBNET, port DASHBOARD_PORT only). This box has a single
# NIC serving both LAN and (via the router's own port-forwarding of just
# the OpenVPN port) WAN-origin traffic, so a specific bind address was never
# really a second security layer here -- it just meant the dashboard broke
# every time the box's own LAN address changed. The firewall is the actual
# boundary; nftables failing open is the scenario that matters, and no
# amount of bind-address cleverness here protects against that.
import html
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_file, send_from_directory
from werkzeug.serving import run_simple

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
CONF_PATH = Path("/etc/home-base/homebase.conf")

_KV_RE = re.compile(r'^([A-Z_][A-Z0-9_]*)=["\']?(.*?)["\']?\s*(?:#.*)?$')


def _parse_kv_file(path):
    values = {}
    if not path.exists():
        return values
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _KV_RE.match(line)
        if m:
            values[m.group(1)] = m.group(2)
    return values


def load_config():
    return _parse_kv_file(CONF_PATH)


def save_config_values(updates):
    """In-place KEY="value" replacement in homebase.conf, appending any key
    that isn't already present. A blank value for a key already in
    `updates` still overwrites -- callers that want "leave unchanged" need
    to simply omit that key rather than pass an empty string for it."""
    text = CONF_PATH.read_text() if CONF_PATH.exists() else ""
    for key, value in updates.items():
        pattern = re.compile(rf'^{re.escape(key)}=.*$', re.MULTILINE)
        line = f'{key}="{value}"'
        if pattern.search(text):
            text = pattern.sub(line, text)
        else:
            text = text.rstrip("\n") + f"\n{line}\n"
    CONF_PATH.write_text(text)


def run(cmd, timeout=10):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip(), out.stderr.strip(), out.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return "", str(e), 1


class WhitelistSyncError(Exception):
    """Anything that means a sync attempt has to abort *without* touching
    the nftables set -- a fetch failure, a malformed response, a failure to
    even read current state. Never let a transient error (network blip,
    GitHub outage, auth hiccup) result in the whitelist going empty; better
    to leave last-known-good elements in place than risk locking the admin
    out over something that will resolve itself next poll."""


# ---------------------------------------------------------------------------
# Whitelist source fetchers
# ---------------------------------------------------------------------------
def fetch_github_gist(gist_id, token):
    if not gist_id or not token:
        raise WhitelistSyncError("GIST_ID and GIST_TOKEN are both required for SOURCE_TYPE=github_gist")
    req = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "home-base",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise WhitelistSyncError(f"GitHub API returned HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise WhitelistSyncError(f"failed to reach GitHub API: {e}") from e
    except json.JSONDecodeError as e:
        raise WhitelistSyncError(f"GitHub API returned unparseable JSON: {e}") from e

    files = data.get("files") or {}
    if not files:
        raise WhitelistSyncError("gist has no files")
    # Whatever the first file is -- a whitelist gist is expected to hold
    # exactly one file. dict insertion order here matches the API response
    # order, so this is deterministic even with more than one file.
    first_file = next(iter(files.values()))
    content = first_file.get("content")
    if content is None:
        raise WhitelistSyncError("gist file has no content (gist's API truncates files over 1MB)")
    return content


def fetch_raw_url(url):
    if not url:
        raise WhitelistSyncError("SOURCE_URL is required for SOURCE_TYPE=raw_url")
    req = urllib.request.Request(url, headers={"User-Agent": "home-base"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise WhitelistSyncError(f"source URL returned HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise WhitelistSyncError(f"failed to reach source URL: {e}") from e


def fetch_whitelist_text(conf):
    source_type = conf.get("SOURCE_TYPE", "")
    if source_type == "github_gist":
        return fetch_github_gist(conf.get("GIST_ID", ""), conf.get("GIST_TOKEN", ""))
    if source_type == "raw_url":
        return fetch_raw_url(conf.get("SOURCE_URL", ""))
    raise WhitelistSyncError(f"unknown SOURCE_TYPE: {source_type!r} (expected github_gist or raw_url)")


# ---------------------------------------------------------------------------
# Whitelist parsing
# ---------------------------------------------------------------------------
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b[^>]*>.*?</\1>")
_BLOCK_BREAK_RE = re.compile(r"(?i)</(p|div|li|h[1-6]|tr)>|<br\s*/?>")
_TAG_RE = re.compile(r"<[^>]+>")


def _html_to_text(raw):
    """Best-effort HTML-to-text: strips script/style blocks entirely,
    turns block-level closing tags into newlines (so each paragraph/row
    stays on its own line), strips remaining tags, unescapes entities.

    Applied unconditionally, not just when a source "looks like" HTML --
    a genuinely plain-text source has no `<...>` sequences for this to
    match, so it's a no-op there. This exists because Google Docs'
    "publish to web" URL (a real, working raw_url source, not a
    misconfiguration) doesn't actually serve plain text -- it serves a
    full styled HTML+JS page for browser rendering, with each line/
    paragraph in its own block element and no literal newlines between
    them in the raw response at all.

    Google's published-page chrome around the actual document (title
    banner, "Published using Google Docs", "Report abuse", the
    "Updated automatically every N minutes" caption) would otherwise show
    up as bogus parse warnings on every sync even though the real content
    parses fine -- so if a `doc-content` marker is present (Google's own
    wrapper around just the real document body), only what's between that
    and the trailing <script> block is processed, skipping the chrome
    entirely rather than just tolerating it as noise."""
    body = raw
    doc_content_at = raw.find("doc-content")
    if doc_content_at != -1:
        # "doc-content" is a class name inside the wrapping <div ...> tag's
        # attributes (e.g. class="c2 doc-content"), not a tag boundary --
        # skip to the end of that opening tag (the next '>') so its own
        # markup doesn't end up glued onto the first real line of content.
        tag_end = raw.find(">", doc_content_at)
        body_start = tag_end + 1 if tag_end != -1 else doc_content_at
        script_at = raw.find("<script", body_start)
        body = raw[body_start : script_at if script_at != -1 else None]

    text = _SCRIPT_STYLE_RE.sub("", body)
    text = _BLOCK_BREAK_RE.sub("\n", text)
    text = _TAG_RE.sub("", text)
    return html.unescape(text)


def parse_whitelist(text):
    """Returns (entries, warnings). entries is a set of normalized IPv4
    host/CIDR strings, in the same string form get_current_elements()
    produces for existing nft elements, so the two sets are directly
    comparable. warnings lists lines that didn't parse, so a typo in the
    whitelist doc surfaces on the dashboard instead of being silently
    dropped from the sync."""
    text = _html_to_text(text)
    entries = set()
    warnings = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            if "/" in line:
                net = ipaddress.IPv4Network(line, strict=False)
                entries.add(str(net))
            else:
                entries.add(str(ipaddress.IPv4Address(line)))
        except ValueError:
            warnings.append(f"line {lineno}: {raw_line.strip()!r} is not a valid IPv4 address or CIDR block")
    return entries, warnings


# ---------------------------------------------------------------------------
# nftables set sync
# ---------------------------------------------------------------------------
def get_current_elements(family, table, set_name):
    out, err, rc = run(["nft", "-j", "list", "set", family, table, set_name])
    if rc != 0:
        raise WhitelistSyncError(f"failed to read nftables set {family} {table} {set_name}: {err or out}")
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        raise WhitelistSyncError(f"nft -j produced unparseable JSON: {e}") from e

    elements = set()
    for obj in data.get("nftables", []):
        set_obj = obj.get("set")
        if not set_obj:
            continue
        for elem in set_obj.get("elem", []):
            if isinstance(elem, str):
                elements.add(elem)
            elif isinstance(elem, dict) and "prefix" in elem:
                prefix = elem["prefix"]
                elements.add(f"{prefix['addr']}/{prefix['len']}")
            # Any other element shape (e.g. a range) isn't something this
            # whitelist format produces -- skip rather than crash on it.
    return elements


def apply_diff(family, table, set_name, current, desired):
    """Adds/removes only the difference -- never flushes -- so the set is
    never briefly empty. Adds happen before removes, so a same-cycle
    replace (new IP in, old IP out) never has a window where neither is
    present."""
    to_add = sorted(desired - current)
    to_remove = sorted(current - desired)

    if to_add:
        elements = "{ " + ", ".join(to_add) + " }"
        _, err, rc = run(["nft", "add", "element", family, table, set_name, elements])
        if rc != 0:
            raise WhitelistSyncError(f"failed to add {to_add}: {err}")

    if to_remove:
        elements = "{ " + ", ".join(to_remove) + " }"
        _, err, rc = run(["nft", "delete", "element", family, table, set_name, elements])
        if rc != 0:
            raise WhitelistSyncError(f"failed to remove {to_remove}: {err}")

    return to_add, to_remove


# ---------------------------------------------------------------------------
# Orchestration + shared state (read by the dashboard, written by the
# background sync loop and by manually-triggered syncs alike)
# ---------------------------------------------------------------------------
_state_lock = threading.Lock()
_state = {
    "last_sync": None,
    "last_success": None,
    "status": "never_run",  # never_run | ok | error
    "message": None,
    "warnings": [],
    "added": [],
    "removed": [],
    "current_elements": [],
}


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def get_state():
    with _state_lock:
        return dict(_state)


def run_sync_once(conf):
    family = conf.get("NFT_FAMILY", "inet")
    table = conf.get("NFT_TABLE", "filter")
    set_name = conf.get("NFT_SET", "vpn_allowed")
    now = _iso_now()

    try:
        text = fetch_whitelist_text(conf)
        desired, warnings = parse_whitelist(text)
        current = get_current_elements(family, table, set_name)
        added, removed = apply_diff(family, table, set_name, current, desired)
        with _state_lock:
            _state.update(
                {
                    "last_sync": now,
                    "last_success": now,
                    "status": "ok",
                    "message": None,
                    "warnings": warnings,
                    "added": added,
                    "removed": removed,
                    "current_elements": sorted(desired),
                }
            )
    except WhitelistSyncError as e:
        with _state_lock:
            _state.update({"last_sync": now, "status": "error", "message": str(e)})

    return get_state()


# ---------------------------------------------------------------------------
# Background sync loop
# ---------------------------------------------------------------------------
_stop_event = threading.Event()


def _sync_loop():
    # Reloads config fresh every iteration rather than capturing it once at
    # thread start -- a source change saved through the dashboard (see
    # api_source_save) would otherwise not take effect until the service
    # restarts, silently syncing against stale settings in the meantime.
    while not _stop_event.is_set():
        conf = load_config()
        run_sync_once(conf)
        interval = max(int(conf.get("POLL_INTERVAL_SECONDS", "120")), 15)
        _stop_event.wait(interval)


def get_source_summary(conf):
    """GIST_TOKEN is never echoed back -- that's a real credential. The URL
    itself is shown, though: unlike a password, whoever configured it
    already has it, and being able to see what's actually set on this
    LAN/loopback-only dashboard (rather than needing to SSH in and grep
    homebase.conf to check) is worth more than the marginal extra exposure
    of it appearing here."""
    source_type = conf.get("SOURCE_TYPE", "")
    summary = {"source_type": source_type}
    if source_type == "github_gist":
        summary["gist_id"] = conf.get("GIST_ID") or None
        summary["gist_token_configured"] = bool(conf.get("GIST_TOKEN"))
    elif source_type == "raw_url":
        summary["source_url"] = conf.get("SOURCE_URL") or None
    return summary


def save_source_config(payload):
    source_type = payload.get("source_type") or ""
    if source_type not in ("github_gist", "raw_url"):
        return False, "source_type must be 'github_gist' or 'raw_url'"

    updates = {"SOURCE_TYPE": source_type}
    if source_type == "raw_url":
        url = (payload.get("source_url") or "").strip()
        if not url:
            return False, "URL is required"
        updates["SOURCE_URL"] = url
    else:
        gist_id = (payload.get("gist_id") or "").strip()
        if not gist_id:
            return False, "Gist ID is required"
        updates["GIST_ID"] = gist_id
        # Blank means "keep the current token" -- never echoed back to the
        # client to prefill, so this is the only way to leave it unchanged.
        token = payload.get("gist_token") or ""
        if token:
            updates["GIST_TOKEN"] = token

    save_config_values(updates)
    return True, None


# ---------------------------------------------------------------------------
# OpenVPN client certificates -- generated via the same easy-rsa PKI
# install.sh sets up (fresh) or finds already there (adopted). Always at a
# fixed path regardless of which: install.sh's fresh-provision path uses the
# same /etc/openvpn/easy-rsa layout as an adopted, already-existing server.
# ---------------------------------------------------------------------------
EASYRSA_DIR = Path("/etc/openvpn/easy-rsa")
OPENVPN_SERVER_DIR = Path("/etc/openvpn/server")

_CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CertError(Exception):
    """Client cert generation/listing failed."""


def _valid_client_name(name):
    return bool(_CLIENT_NAME_RE.match(name or ""))


def list_vpn_clients(conf):
    """Parses pki/index.txt directly rather than shelling out to easyrsa for
    a listing -- index.txt's format is stable/documented and this avoids
    another subprocess round-trip just to show a list."""
    index_path = EASYRSA_DIR / "pki" / "index.txt"
    if not index_path.exists():
        return []

    ca_cn = conf.get("EASYRSA_REQ_CN", "")
    excluded = {"server", ca_cn} if ca_cn else {"server"}

    clients = []
    for line in index_path.read_text().splitlines():
        fields = line.split("\t")
        if len(fields) < 6:
            continue
        status, expiry, revoke_date, serial, _filename, subject = fields[:6]
        m = re.search(r"/CN=([^/]+)", subject)
        if not m:
            continue
        cn = m.group(1)
        if cn in excluded:
            continue
        clients.append(
            {
                "name": cn,
                "status": {"V": "valid", "R": "revoked", "E": "expired"}.get(status, status),
                "expires": expiry or None,
                "revoked_at": revoke_date or None,
            }
        )
    return clients


def _extract_pem(text, label):
    m = re.search(rf"-----BEGIN {label}-----.*?-----END {label}-----", text, re.DOTALL)
    if not m:
        raise CertError(f"couldn't find a {label} PEM block where one was expected")
    return m.group(0)


def _build_ovpn_bundle(conf, client_name):
    remote = conf.get("VPN_REMOTE_HOST", "")
    if not remote:
        raise CertError("VPN_REMOTE_HOST isn't set in homebase.conf -- can't generate a usable client config without it")
    port = conf.get("OPENVPN_PORT", "1194")
    proto = conf.get("OPENVPN_PROTO", "udp")

    ca_path = OPENVPN_SERVER_DIR / "ca.crt"
    tc_path = OPENVPN_SERVER_DIR / "tc.key"
    cert_path = EASYRSA_DIR / "pki" / "issued" / f"{client_name}.crt"
    key_path = EASYRSA_DIR / "pki" / "private" / f"{client_name}.key"
    for p in (ca_path, tc_path, cert_path, key_path):
        if not p.exists():
            raise CertError(f"expected file missing: {p}")

    ca_pem = _extract_pem(ca_path.read_text(), "CERTIFICATE")
    cert_pem = _extract_pem(cert_path.read_text(), "CERTIFICATE")
    key_pem = _extract_pem(key_path.read_text(), "PRIVATE KEY")
    tc_pem = _extract_pem(tc_path.read_text(), "OpenVPN Static key V1")

    return f"""client
dev tun
proto {proto}
remote {remote} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
tls-version-min 1.2
verb 3

<ca>
{ca_pem}
</ca>

<cert>
{cert_pem}
</cert>

<key>
{key_pem}
</key>

<tls-crypt>
{tc_pem}
</tls-crypt>
"""


def generate_vpn_client(conf, name):
    if not _valid_client_name(name):
        return False, "Name must be 1-64 characters: letters, numbers, dots, dashes, underscores only.", None

    ca_cn = conf.get("EASYRSA_REQ_CN", "")
    if name == "server" or (ca_cn and name == ca_cn):
        return False, f'"{name}" is reserved (used by the server/CA cert itself).', None

    cert_path = EASYRSA_DIR / "pki" / "issued" / f"{name}.crt"
    if cert_path.exists():
        return False, f'A cert named "{name}" already exists.', None

    if not (EASYRSA_DIR / "easyrsa").exists():
        return False, "No easy-rsa PKI found at /etc/openvpn/easy-rsa -- is OpenVPN set up yet?", None

    env = dict(os.environ)
    env["EASYRSA_REQ_CN"] = name
    result = subprocess.run(
        ["./easyrsa", "build-client-full", name, "nopass"],
        cwd=str(EASYRSA_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return False, f"easyrsa failed: {result.stderr.strip() or result.stdout.strip()}", None

    try:
        bundle = _build_ovpn_bundle(conf, name)
    except CertError as e:
        return False, f"cert was issued, but bundling the .ovpn file failed: {e}", None

    return True, None, bundle


def redownload_vpn_client(conf, name):
    """Re-assembles the .ovpn bundle for an already-issued cert -- nothing
    is regenerated, this just re-reads the same files on disk that
    generate_vpn_client() built the first time."""
    if not _valid_client_name(name):
        return False, "invalid name", None
    cert_path = EASYRSA_DIR / "pki" / "issued" / f"{name}.crt"
    if not cert_path.exists():
        return False, f'No active cert named "{name}" found (it may have been revoked).', None
    try:
        bundle = _build_ovpn_bundle(conf, name)
    except CertError as e:
        return False, str(e), None
    return True, None, bundle


def revoke_vpn_client(conf, name):
    """Revokes the cert (easyrsa moves it out of pki/issued -- the private
    key stays on disk but the issued cert doesn't, so a subsequent
    redownload_vpn_client() naturally and correctly fails), regenerates the
    CRL, and copies it to where the running server actually reads it from
    (crl-verify's path is relative to /etc/openvpn/server, not the PKI dir
    -- copying is required for the revocation to actually take effect, not
    just optional bookkeeping)."""
    if not _valid_client_name(name):
        return False, "invalid name"
    ca_cn = conf.get("EASYRSA_REQ_CN", "")
    if name == "server" or (ca_cn and name == ca_cn):
        return False, f'"{name}" is reserved (used by the server/CA cert itself).'

    cert_path = EASYRSA_DIR / "pki" / "issued" / f"{name}.crt"
    if not cert_path.exists():
        return False, f'No active cert named "{name}" found (already revoked, or never existed).'

    env = dict(os.environ)
    result = subprocess.run(
        ["./easyrsa", "revoke", name],
        cwd=str(EASYRSA_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return False, f"easyrsa revoke failed: {result.stderr.strip() or result.stdout.strip()}"

    crl_result = subprocess.run(
        ["./easyrsa", "gen-crl"],
        cwd=str(EASYRSA_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if crl_result.returncode != 0:
        return False, f"revoked, but gen-crl failed: {crl_result.stderr.strip() or crl_result.stdout.strip()}"

    new_crl = EASYRSA_DIR / "pki" / "crl.pem"
    if new_crl.exists():
        OPENVPN_SERVER_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(new_crl, OPENVPN_SERVER_DIR / "crl.pem")
        (OPENVPN_SERVER_DIR / "crl.pem").chmod(0o600)

    return True, None


# ---------------------------------------------------------------------------
# Live connections -- distinct from the certificate list above. OpenVPN's
# own --status file (version 2, CSV) is the only source of truth for who is
# actually connected right now; a "valid" cert says nothing about that.
# ---------------------------------------------------------------------------
OPENVPN_STATUS_LOG = Path("/var/log/openvpn/server-status.log")


def get_active_vpn_connections():
    if not OPENVPN_STATUS_LOG.exists():
        return []
    connections = []
    for line in OPENVPN_STATUS_LOG.read_text().splitlines():
        if not line.startswith("CLIENT_LIST,"):
            continue
        fields = line.split(",")
        if len(fields) < 9:
            continue
        connections.append(
            {
                "name": fields[1],
                "real_address": fields[2],
                "virtual_address": fields[3],
                "bytes_received": int(fields[5]) if fields[5].isdigit() else None,
                "bytes_sent": int(fields[6]) if fields[6].isdigit() else None,
                "connected_since": fields[7],
            }
        )
    return connections


# ---------------------------------------------------------------------------
# Backup bundle -- the CA private key especially: lose it and every issued
# client cert becomes permanently unmanageable (can't issue new ones from
# the same trust chain, can't revoke old ones). Built in memory, never
# written to disk here, so there's no plaintext copy of it left behind by
# the act of downloading a copy.
# ---------------------------------------------------------------------------
_BACKUP_PATHS = [
    EASYRSA_DIR / "pki" / "ca.crt",
    EASYRSA_DIR / "pki" / "private" / "ca.key",
    EASYRSA_DIR / "pki" / "crl.pem",
    OPENVPN_SERVER_DIR / "server.crt",
    OPENVPN_SERVER_DIR / "server.key",
    OPENVPN_SERVER_DIR / "tc.key",
    Path("/etc/home-base/homebase.conf"),
]


def build_backup_archive():
    buf = io.BytesIO()
    included = []
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in _BACKUP_PATHS:
            if path.exists():
                tar.add(path, arcname=f"home-base-backup/{path.name}")
                included.append(str(path))
    buf.seek(0)
    return buf, included


app = Flask(__name__, static_folder=None)


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)


@app.route("/api/status")
def api_status():
    conf = load_config()
    state = get_state()
    return jsonify(
        {
            "source": get_source_summary(conf),
            "nft_target": {
                "family": conf.get("NFT_FAMILY", "inet"),
                "table": conf.get("NFT_TABLE", "filter"),
                "set": conf.get("NFT_SET", "vpn_allowed"),
            },
            "poll_interval_seconds": int(conf.get("POLL_INTERVAL_SECONDS", "120")),
            **state,
        }
    )


@app.route("/api/sync", methods=["POST"])
def api_sync():
    conf = load_config()
    state = run_sync_once(conf)
    status_code = 200 if state["status"] == "ok" else 502
    return jsonify(state), status_code


@app.route("/api/source", methods=["POST"])
def api_source_save():
    payload = request.get_json(silent=True) or {}
    ok, message = save_source_config(payload)
    if not ok:
        return jsonify({"status": "error", "message": message}), 400

    # Immediately sync against the new settings -- this is the "check that
    # it can reach the URL and see that it's parsed properly" step, as a
    # side effect of just doing the real thing rather than a separate
    # dry-run mode.
    conf = load_config()
    state = run_sync_once(conf)
    status_code = 200 if state["status"] == "ok" else 502
    return jsonify(state), status_code


@app.route("/api/vpn-clients")
def api_vpn_clients():
    conf = load_config()
    return jsonify(list_vpn_clients(conf))


@app.route("/api/vpn-clients", methods=["POST"])
def api_vpn_clients_create():
    conf = load_config()
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()

    ok, message, bundle = generate_vpn_client(conf, name)
    if not ok:
        return jsonify({"status": "error", "message": message}), 400
    return jsonify({"status": "ok", "name": name, "ovpn_config": bundle})


@app.route("/api/vpn-clients/<name>/download")
def api_vpn_clients_download(name):
    conf = load_config()
    ok, message, bundle = redownload_vpn_client(conf, name)
    if not ok:
        return jsonify({"status": "error", "message": message}), 404
    return jsonify({"status": "ok", "name": name, "ovpn_config": bundle})


@app.route("/api/vpn-clients/<name>", methods=["DELETE"])
def api_vpn_clients_revoke(name):
    conf = load_config()
    ok, message = revoke_vpn_client(conf, name)
    if not ok:
        return jsonify({"status": "error", "message": message}), 400
    return jsonify({"status": "ok"})


@app.route("/api/active-connections")
def api_active_connections():
    return jsonify(get_active_vpn_connections())


@app.route("/api/backup")
def api_backup():
    buf, included = build_backup_archive()
    if not included:
        return jsonify({"status": "error", "message": "nothing found to back up yet"}), 404
    return send_file(
        buf,
        mimetype="application/gzip",
        as_attachment=True,
        download_name="home-base-backup.tar.gz",
    )


def main():
    conf = load_config()
    port = int(conf.get("DASHBOARD_PORT", "8081"))

    threading.Thread(target=_sync_loop, daemon=True).start()
    run_simple("0.0.0.0", port, app, threaded=True)


if __name__ == "__main__":
    main()
