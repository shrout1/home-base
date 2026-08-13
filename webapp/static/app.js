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

  let detail = "—";
  if (data.source.source_type === "github_gist") {
    const idPart = data.source.gist_id ? `gist ${data.source.gist_id}` : "no gist ID set";
    detail = `${idPart}, token ${data.source.gist_token_configured ? "configured" : "MISSING"}`;
  } else if (data.source.source_type === "raw_url") {
    detail = data.source.source_url_configured ? "URL configured" : "URL MISSING";
  }
  setText("source-detail", detail);

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
  }
  updateSourceFormVisibility();
}

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
    label.textContent = `${c.name} — ${c.real_address}, since ${c.connected_since}`;
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
    const res = await fetch("/api/active-connections");
    if (!res.ok) return;
    renderActiveConnections(await res.json());
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
setInterval(poll, POLL_MS);
setInterval(loadClients, POLL_MS * 4);
setInterval(loadActiveConnections, POLL_MS);
