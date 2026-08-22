const POLL_MS = 5000;

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text ?? "—";
}

function fmtTime(iso) {
  if (!iso) return "never";
  return new Date(iso).toLocaleString();
}

function renderPillList(id, items, className) {
  const list = document.getElementById(id);
  list.innerHTML = "";
  if (!items || !items.length) {
    list.className = "pill-list empty";
    list.innerHTML = "<li>none</li>";
    return;
  }
  list.className = "pill-list";
  for (const item of items) {
    const li = document.createElement("li");
    if (className) li.className = className;
    li.textContent = item;
    list.appendChild(li);
  }
}

function renderSource(data) {
  setText("source-type", data.source.source_type || "not configured");

  const detailEl = document.getElementById("source-detail");
  if (data.source.source_type === "raw_url" && data.source.source_url) {
    // A real <a>, not textContent -- so it's actually clickable to open the
    // whitelist doc directly, instead of the admin having to copy/paste it.
    detailEl.innerHTML = "";
    const link = document.createElement("a");
    link.href = data.source.source_url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = data.source.source_url;
    detailEl.appendChild(link);
  } else if (data.source.source_type === "github_gist") {
    const idPart = data.source.gist_id ? `gist ${data.source.gist_id}` : "no gist ID set";
    setText("source-detail", `${idPart}, token ${data.source.gist_token_configured ? "configured" : "MISSING"}`);
  } else {
    setText("source-detail", data.source.source_type === "raw_url" ? "URL MISSING" : "—");
  }

  setText("nft-target", `${data.nft_target.family} ${data.nft_target.table} ${data.nft_target.set}`);
  setText("poll-interval", `${data.poll_interval_seconds}s`);
}

function renderSync(data) {
  const status = document.getElementById("sync-status");
  status.textContent = data.status;
  status.className = `status ${data.status}`;
  setText("sync-last", fmtTime(data.last_sync));
  setText("sync-last-success", fmtTime(data.last_success));

  const message = document.getElementById("sync-message");
  if (data.status === "error" && data.message) {
    message.textContent = data.message;
    message.className = "message error";
  } else {
    message.textContent = "";
    message.className = "message";
  }

  const warnings = document.getElementById("sync-warnings");
  if (data.warnings && data.warnings.length) {
    warnings.hidden = false;
    // textContent, not innerHTML -- these strings echo back whatever the
    // whitelist source served (a misbehaving or compromised source could
    // otherwise inject markup/script into this page).
    warnings.innerHTML = "";
    for (const w of data.warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      warnings.appendChild(li);
    }
  } else {
    warnings.hidden = true;
  }
}

function renderCurrent(data) {
  renderPillList("current-elements", data.current_elements);
}

function renderChanges(data) {
  const list = document.getElementById("last-changes");
  const added = (data.added || []).map((ip) => ({ ip, cls: "added" }));
  const removed = (data.removed || []).map((ip) => ({ ip, cls: "removed" }));
  const combined = [...added, ...removed];
  if (!combined.length) {
    list.className = "pill-list empty";
    list.innerHTML = "<li>no changes</li>";
    return;
  }
  list.className = "pill-list";
  list.innerHTML = combined
    .map((c) => `<li class="${c.cls}">${c.cls === "added" ? "+" : "−"} ${c.ip}</li>`)
    .join("");
}

function renderPublicIp(data) {
  setText("public-ip-checked", fmtTime(data.checked_at));
  setText("public-ip", data.public_ip || (data.public_ip_error ? "unreachable" : "—"));
  setText("ddns-hostname", data.vpn_remote_host || "not set");
  setText("ddns-resolved", data.resolved_ip || (data.resolve_error ? "resolution failed" : "—"));

  const syncEl = document.getElementById("ddns-sync-status");
  if (data.in_sync === true) {
    syncEl.textContent = "yes";
    syncEl.className = "status ok";
  } else if (data.in_sync === false) {
    syncEl.textContent = "MISMATCH -- hostname points at a stale IP";
    syncEl.className = "status error";
  } else {
    syncEl.textContent = "unknown";
    syncEl.className = "status unknown";
  }

  const noipEl = document.getElementById("noip-service-status");
  if (!data.noip_installed) {
    noipEl.textContent = "not installed";
    noipEl.className = "status unknown";
  } else if (data.noip_active) {
    noipEl.textContent = "active";
    noipEl.className = "status ok";
  } else {
    noipEl.textContent = "inactive -- DDNS record won't update if your IP changes";
    noipEl.className = "status error";
  }
}

let latestPublicIpData = null;

function populateDdnsFieldsForSelectedService() {
  const service = document.getElementById("ddns-service-select").value;
  if (service === "noip" && latestPublicIpData) {
    document.getElementById("ddns-username-input").value = latestPublicIpData.noip_username || "";
    document.getElementById("ddns-hostnames-input").value = latestPublicIpData.noip_hostnames || "";
    document.getElementById("ddns-password-input").value = "";
  }
}

document.getElementById("ddns-service-select").addEventListener("change", populateDdnsFieldsForSelectedService);

async function syncDdnsNow() {
  const btn = document.getElementById("ddns-sync-now");
  const message = document.getElementById("ddns-sync-message");
  btn.disabled = true;
  message.textContent = "Restarting noip-duc and checking…";
  message.className = "message";
  try {
    const res = await fetch("/api/ddns/sync", { method: "POST" });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      latestPublicIpData = data;
      renderPublicIp(data);
      message.textContent = data.in_sync
        ? "Synced -- hostname matches your current public IP."
        : "Checked -- see status above.";
      message.className = "message ok";
    } else {
      message.textContent = data.message || "Sync failed.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("ddns-sync-now").addEventListener("click", syncDdnsNow);

let ddnsFormInitialized = false;

function prefillDdnsForm(data) {
  // Only auto-prefill once, on initial load -- a poll landing mid-edit
  // shouldn't stomp on whatever the user is currently typing. Explicitly
  // switching the service dropdown (once more than one exists) re-populates
  // on purpose, via the change listener above. Password is never sent back
  // by the API, so there's nothing to prefill it with.
  if (ddnsFormInitialized) return;
  ddnsFormInitialized = true;
  populateDdnsFieldsForSelectedService();
}

async function loadPublicIp() {
  try {
    const res = await fetch("/api/public-ip");
    if (!res.ok) return;
    const data = await res.json();
    latestPublicIpData = data;
    renderPublicIp(data);
    prefillDdnsForm(data);
  } catch (err) {
    // non-fatal -- next poll cycle retries
  }
}

async function saveDdns() {
  const btn = document.getElementById("ddns-save");
  const message = document.getElementById("ddns-message");
  const username = document.getElementById("ddns-username-input").value.trim();
  const password = document.getElementById("ddns-password-input").value;
  const hostnames = document.getElementById("ddns-hostnames-input").value.trim();

  if (!username || !hostnames) {
    message.textContent = "Username and hostname(s) are required.";
    message.className = "message error";
    return;
  }

  btn.disabled = true;
  message.textContent = "Saving and restarting service…";
  message.className = "message";
  try {
    const res = await fetch("/api/ddns", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, hostnames }),
    });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = "Saved -- service restarted. Check the Public IP / DDNS card above shortly to confirm it's syncing.";
      message.className = "message ok";
      document.getElementById("ddns-password-input").value = "";
    } else {
      message.textContent = data.message || "Failed to save.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    btn.disabled = false;
    loadPublicIp();
  }
}

document.getElementById("ddns-save").addEventListener("click", saveDdns);

let backendVisibilityInitialized = false;

function updateBackendVisibility(data) {
  // Only set once -- these are enable/disable toggles from homebase.conf,
  // not something that flips during a normal running session.
  if (backendVisibilityInitialized) return;
  backendVisibilityInitialized = true;
  document.getElementById("card-clients").hidden = !data.openvpn_enabled;
  document.getElementById("card-wg-clients").hidden = !data.wireguard_enabled;
  document.getElementById("card-active-clients").hidden = !data.openvpn_enabled && !data.wireguard_enabled;
}

async function poll() {
  const indicator = document.getElementById("refresh-indicator");
  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderSource(data);
    renderSync(data);
    renderCurrent(data);
    renderChanges(data);
    prefillSourceForm(data);
    prefillPollIntervalForm(data);
    updateBackendVisibility(data);
    indicator.classList.remove("stale");
  } catch (err) {
    indicator.classList.add("stale");
  }
}

async function syncNow() {
  const btn = document.getElementById("sync-now");
  btn.disabled = true;
  btn.textContent = "Syncing…";
  try {
    await fetch("/api/sync", { method: "POST" });
  } catch (err) {
    // non-fatal -- poll() below reflects the real outcome regardless
  } finally {
    btn.disabled = false;
    btn.textContent = "Sync now";
    poll();
  }
}

document.getElementById("sync-now").addEventListener("click", syncNow);

// --- Source configuration -------------------------------------------------

function updateSourceFormVisibility() {
  const type = document.getElementById("source-type-select").value;
  document.getElementById("source-url-help").hidden = type !== "raw_url";
  document.getElementById("source-url-field").hidden = type !== "raw_url";
  document.getElementById("source-gist-id-field").hidden = type !== "github_gist";
  document.getElementById("source-gist-token-field").hidden = type !== "github_gist";
}

document.getElementById("source-type-select").addEventListener("change", updateSourceFormVisibility);

let sourceFormInitialized = false;

function prefillSourceForm(data) {
  // Only prefill once -- a poll landing mid-edit shouldn't stomp on
  // whatever the user is currently typing.
  if (sourceFormInitialized) return;
  sourceFormInitialized = true;
  const type = data.source.source_type;
  if (type) document.getElementById("source-type-select").value = type;
  if (type === "github_gist" && data.source.gist_id) {
    document.getElementById("source-gist-id-input").value = data.source.gist_id;
  } else if (type === "raw_url" && data.source.source_url) {
    document.getElementById("source-url-input").value = data.source.source_url;
  }
  updateSourceFormVisibility();
}

let pollIntervalFormInitialized = false;

function prefillPollIntervalForm(data) {
  if (pollIntervalFormInitialized) return;
  pollIntervalFormInitialized = true;
  document.getElementById("poll-interval-input").value = data.poll_interval_seconds;
}

async function savePollInterval() {
  const btn = document.getElementById("poll-interval-save");
  const message = document.getElementById("poll-interval-message");
  const input = document.getElementById("poll-interval-input");
  const seconds = parseInt(input.value, 10);

  if (!Number.isInteger(seconds) || seconds < 15) {
    message.textContent = "Enter a whole number of seconds, at least 15.";
    message.className = "message error";
    return;
  }

  btn.disabled = true;
  message.textContent = "Saving…";
  message.className = "message";
  try {
    const res = await fetch("/api/poll-interval", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ poll_interval_seconds: seconds }),
    });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = `Saved -- syncing every ${seconds}s. Takes effect on the sync loop's next cycle.`;
      message.className = "message ok";
    } else {
      message.textContent = data.message || "Failed to save.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    btn.disabled = false;
    poll();
  }
}

document.getElementById("poll-interval-save").addEventListener("click", savePollInterval);

async function saveSource() {
  const btn = document.getElementById("source-save");
  const message = document.getElementById("source-message");
  const type = document.getElementById("source-type-select").value;
  const body = { source_type: type };
  if (type === "raw_url") {
    body.source_url = document.getElementById("source-url-input").value.trim();
  } else {
    body.gist_id = document.getElementById("source-gist-id-input").value.trim();
    body.gist_token = document.getElementById("source-gist-token-input").value;
  }

  btn.disabled = true;
  message.textContent = "Saving and testing…";
  message.className = "message";
  try {
    const res = await fetch("/api/source", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = `Saved and synced -- ${data.current_elements.length} entr${data.current_elements.length === 1 ? "y" : "ies"} in the whitelist.`;
      message.className = "message ok";
      document.getElementById("source-gist-token-input").value = "";
    } else {
      message.textContent = `Saved, but the sync failed: ${data.message || "unknown error"}`;
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    btn.disabled = false;
    poll();
  }
}

document.getElementById("source-save").addEventListener("click", saveSource);
updateSourceFormVisibility();

// --- VPN clients -----------------------------------------------------------

function renderClients(clients) {
  const list = document.getElementById("client-list");
  if (!clients || !clients.length) {
    list.className = "row-list empty";
    list.innerHTML = "<li>none yet</li>";
    return;
  }
  list.className = "row-list";
  list.innerHTML = "";
  for (const c of clients) {
    // textContent, not innerHTML -- a cert's CN could contain arbitrary
    // text if it was ever issued outside this dashboard's own name
    // validation (e.g. directly via easyrsa).
    const li = document.createElement("li");
    const revoked = c.status === "revoked";
    if (revoked) li.className = "revoked";

    const label = document.createElement("span");
    label.textContent = `${c.name} (${c.status})`;
    li.appendChild(label);

    if (!revoked) {
      const actions = document.createElement("span");
      actions.className = "row-actions";

      const downloadBtn = document.createElement("button");
      downloadBtn.textContent = "Download";
      downloadBtn.addEventListener("click", () => downloadClient(c.name));
      actions.appendChild(downloadBtn);

      const deleteBtn = document.createElement("button");
      deleteBtn.textContent = "Delete";
      deleteBtn.className = "btn-warn";
      deleteBtn.addEventListener("click", () => deleteClient(c.name));
      actions.appendChild(deleteBtn);

      li.appendChild(actions);
    }
    list.appendChild(li);
  }
}

async function loadClients() {
  try {
    const res = await fetch("/api/vpn-clients");
    if (!res.ok) return;
    renderClients(await res.json());
  } catch (err) {
    // non-fatal -- next poll cycle retries
  }
}

async function downloadClient(name) {
  const message = document.getElementById("client-message");
  message.textContent = `Fetching "${name}"…`;
  message.className = "message";
  try {
    const res = await fetch(`/api/vpn-clients/${encodeURIComponent(name)}/download`);
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      downloadText(`${name}.ovpn`, data.ovpn_config);
      message.textContent = `Downloaded "${name}".`;
      message.className = "message ok";
    } else {
      message.textContent = data.message || "Failed to fetch cert.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  }
}

async function deleteClient(name) {
  if (!window.confirm(`Delete "${name}"? This revokes their certificate immediately and can't be undone.`)) {
    return;
  }
  const message = document.getElementById("client-message");
  message.textContent = `Revoking "${name}"…`;
  message.className = "message";
  try {
    const res = await fetch(`/api/vpn-clients/${encodeURIComponent(name)}`, { method: "DELETE" });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = `Revoked "${name}".`;
      message.className = "message ok";
    } else {
      message.textContent = data.message || "Failed to revoke.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    loadClients();
  }
}

// --- Active clients ---------------------------------------------------

function fmtBytes(bytes) {
  if (bytes == null) return "—";
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

function renderActiveConnections(conns) {
  const list = document.getElementById("active-client-list");
  if (!conns || !conns.length) {
    list.className = "row-list empty";
    list.innerHTML = "<li>nobody connected</li>";
    return;
  }
  list.className = "row-list";
  list.innerHTML = "";
  for (const c of conns) {
    const li = document.createElement("li");

    const label = document.createElement("span");
    const badge = document.createElement("span");
    badge.className = `protocol-badge ${c.protocol.toLowerCase()}`;
    badge.textContent = c.protocol;
    label.appendChild(badge);
    label.appendChild(document.createTextNode(
      c.protocol === "WireGuard"
        ? `${c.name} — ${c.real_address || "unknown endpoint"}, last handshake ${fmtTime(c.connected_since)}`
        : `${c.name} — ${c.real_address}, since ${c.connected_since}`
    ));

    const meta = document.createElement("span");
    meta.className = "row-meta";
    meta.textContent = `${fmtBytes(c.bytes_received)} down / ${fmtBytes(c.bytes_sent)} up`;
    li.appendChild(label);
    li.appendChild(meta);
    list.appendChild(li);
  }
}

async function loadActiveConnections() {
  try {
    const [ovpnRes, wgRes] = await Promise.all([
      fetch("/api/active-connections"),
      fetch("/api/wg-active-connections"),
    ]);
    const ovpn = ovpnRes.ok ? (await ovpnRes.json()).map((c) => ({ ...c, protocol: "OpenVPN" })) : [];
    const wg = wgRes.ok ? (await wgRes.json()).map((c) => ({ ...c, protocol: "WireGuard" })) : [];
    renderActiveConnections([...ovpn, ...wg]);
  } catch (err) {
    // non-fatal -- next poll cycle retries
  }
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "application/x-openvpn-profile" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function generateClient() {
  const btn = document.getElementById("generate-client");
  const message = document.getElementById("client-message");
  const nameInput = document.getElementById("new-client-name");
  const name = nameInput.value.trim();

  if (!name) {
    message.textContent = "A name is required.";
    message.className = "message error";
    return;
  }

  btn.disabled = true;
  message.textContent = "Generating…";
  message.className = "message";
  try {
    const res = await fetch("/api/vpn-clients", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = `Generated "${name}" -- downloading .ovpn now.`;
      message.className = "message ok";
      downloadText(`${name}.ovpn`, data.ovpn_config);
      nameInput.value = "";
      loadClients();
    } else {
      message.textContent = data.message || "Failed to generate cert.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("generate-client").addEventListener("click", generateClient);

// --- WireGuard peers ---------------------------------------------------

function renderWgPeers(peers) {
  const list = document.getElementById("wg-client-list");
  if (!peers || !peers.length) {
    list.className = "row-list empty";
    list.innerHTML = "<li>none yet</li>";
    return;
  }
  list.className = "row-list";
  list.innerHTML = "";
  for (const p of peers) {
    const li = document.createElement("li");

    const label = document.createElement("span");
    label.textContent = `${p.name} (${p.allowed_ips})`;
    li.appendChild(label);

    const actions = document.createElement("span");
    actions.className = "row-actions";

    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = "Delete";
    deleteBtn.className = "btn-warn";
    deleteBtn.addEventListener("click", () => deleteWgPeer(p.name));
    actions.appendChild(deleteBtn);

    li.appendChild(actions);
    list.appendChild(li);
  }
}

async function loadWgPeers() {
  try {
    const res = await fetch("/api/wg-clients");
    if (!res.ok) return;
    renderWgPeers(await res.json());
  } catch (err) {
    // non-fatal -- next poll cycle retries
  }
}

async function deleteWgPeer(name) {
  if (!window.confirm(`Delete peer "${name}"? Their existing config will stop working immediately and can't be undone.`)) {
    return;
  }
  const message = document.getElementById("wg-client-message");
  message.textContent = `Removing "${name}"…`;
  message.className = "message";
  try {
    const res = await fetch(`/api/wg-clients/${encodeURIComponent(name)}`, { method: "DELETE" });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = `Removed "${name}".`;
      message.className = "message ok";
    } else {
      message.textContent = data.message || "Failed to remove peer.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    loadWgPeers();
  }
}

async function generateWgPeer() {
  const btn = document.getElementById("generate-wg-client");
  const message = document.getElementById("wg-client-message");
  const nameInput = document.getElementById("new-wg-client-name");
  const name = nameInput.value.trim();

  if (!name) {
    message.textContent = "A name is required.";
    message.className = "message error";
    return;
  }

  btn.disabled = true;
  message.textContent = "Generating…";
  message.className = "message";
  try {
    const res = await fetch("/api/wg-clients", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const data = await res.json();
    if (res.ok && data.status === "ok") {
      message.textContent = `Generated "${name}" -- downloading config now. Save it; the private key isn't kept server-side.`;
      message.className = "message ok";
      downloadText(`${name}.conf`, data.wg_config);
      nameInput.value = "";
      loadWgPeers();
    } else {
      message.textContent = data.message || "Failed to generate peer.";
      message.className = "message error";
    }
  } catch (err) {
    message.textContent = "Request failed.";
    message.className = "message error";
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("generate-wg-client").addEventListener("click", generateWgPeer);

// --- Backup ------------------------------------------------------------

function downloadBackup() {
  const message = document.getElementById("backup-message");
  message.textContent = "";
  message.className = "message";
  // Plain navigation, not fetch+blob -- send_file's Content-Disposition
  // handles the download, and this avoids holding key material in a JS
  // string/Blob any longer than necessary.
  window.location.href = "/api/backup";
}

document.getElementById("download-backup").addEventListener("click", downloadBackup);

poll();
loadClients();
loadActiveConnections();
loadWgPeers();
loadPublicIp();
setInterval(poll, POLL_MS);
setInterval(loadClients, POLL_MS * 4);
setInterval(loadActiveConnections, POLL_MS);
setInterval(loadWgPeers, POLL_MS * 4);
// Slower cadence -- this hits an external IP-lookup service and does a DNS
// resolution, unlike the other cards which only read local state.
setInterval(loadPublicIp, POLL_MS * 12);
