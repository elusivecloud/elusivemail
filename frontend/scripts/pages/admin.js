import { api, setCsrf } from "../shared/api.js";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
function toast(msg, kind = "ok") {
  const el = document.createElement("div");
  el.className = `admin-toast admin-toast--${kind}`;
  el.textContent = msg;
  $("#toastHost").appendChild(el);
  setTimeout(() => {
    el.classList.add("is-out");
    setTimeout(() => el.remove(), 300);
  }, 2600);
}
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return (n < 10 ? n.toFixed(1) : Math.round(n)) + " " + u[i];
}
function fmtDuration(sec) {
  sec = Number(sec) || 0;
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}
function fmtDate(ts) {
  try {
    return new Date(ts).toLocaleString(void 0, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return "";
  }
}
let myId = null;
async function loadHealth() {
  const r = await api("/api/admin/stats");
  if (!r.ok) return toast(r.data.error || "failed to load stats", "bad");
  const s = r.data;
  const cards = [
    ["Users", s.users.total, `${s.users.new_week} new this week`],
    ["End-to-end", `${s.users.private + s.users.keyfile}/${s.users.total}`, `${s.users.auto} server-key \xB7 ${s.users.keyfile} keyfile`],
    ["2FA enabled", s.users.totp, `${s.users.suspended} suspended \xB7 ${s.users.admins} admin`],
    ["Messages", s.messages.total, `${s.messages.last_24h} in the last 24h`],
    ["In / out", `${s.messages.inbound} / ${s.messages.outbound}`, `${s.messages.e2e} end-to-end`],
    ["Aliases", s.addresses.total, `${s.addresses.temp} disposable \xB7 ${s.groups} personas`],
    ["Database", fmtBytes(s.storage.dbBytes), s.storage.disk ? `${fmtBytes(s.storage.disk.free)} disk free` : "disk usage n/a"],
    ["Attachments", s.attachments.total, fmtBytes(s.storage.attachmentBytes)],
    ["Uptime", fmtDuration(s.process.uptimeSec), `${fmtBytes(s.process.rss)} RAM \xB7 node ${esc(s.process.node)}`]
  ];
  $("#statGrid").innerHTML = cards.map(([label, big, sub]) => `
    <div class="stat">
      <span class="stat__label mono">${esc(label)}</span>
      <span class="stat__big">${esc(String(big))}</span>
      <span class="stat__sub">${esc(sub)}</span>
    </div>`).join("");
  const t = s.transport;
  const dot = (ok) => `<span class="tdot ${ok ? "is-ok" : "is-off"}"></span>`;
  $("#transportRow").innerHTML = `
    <span class="mono transport-label">Mail transport</span>
    <span class="tflag">${dot(true)} ${esc(t.domain)}</span>
    <span class="tflag">${dot(t.production)} production mode</span>
    <span class="tflag">${dot(t.dkim)} DKIM signing</span>
    <span class="tflag">${dot(t.tls)} inbound TLS</span>
    <span class="tflag"><span class="tdot is-neutral"></span> ${t.relay ? "relay " + esc(t.relay) : "direct send"}</span>`;
}
async function loadAccounts() {
  const r = await api("/api/admin/users");
  if (!r.ok) return toast(r.data.error || "failed to load accounts", "bad");
  const rows = r.data.users;
  $("#acctCount").textContent = `${rows.length} account${rows.length === 1 ? "" : "s"}`;
  const head = `<thead><tr>
    <th>User</th><th>Mode</th><th>Aliases</th><th>Stored</th><th>Joined</th><th>Status</th><th></th>
  </tr></thead>`;
  const body = rows.map((u) => {
    const mode = u.enc_mode === "auto" ? "server-key" : u.enc_mode;
    const status = u.suspended ? '<span class="pill pill--bad">suspended</span>' : '<span class="pill pill--ok">active</span>';
    const tags = (u.is_admin ? '<span class="pill pill--admin">admin</span>' : "") + (u.totp_enabled ? '<span class="pill pill--soft">2FA</span>' : "");
    const actions = u.id === myId ? '<span class="mono muted">you</span>' : `
      <button class="btn btn--ghost btn--xs" data-suspend="${u.id}" data-to="${u.suspended ? 0 : 1}">${u.suspended ? "Unsuspend" : "Suspend"}</button>
      <button class="btn btn--xs admin-del" data-del="${u.id}" data-name="${esc(u.username)}">Delete</button>`;
    return `<tr>
      <td><span class="acct-user">${esc(u.username)}</span> ${tags}<div class="mono muted acct-email">${esc(u.email)}</div></td>
      <td>${esc(mode)}</td>
      <td>${u.addresses}</td>
      <td>${fmtBytes(u.body_bytes)}</td>
      <td class="mono muted">${fmtDate(u.created_at)}</td>
      <td>${status}</td>
      <td class="acct-actions">${actions}</td>
    </tr>`;
  }).join("");
  $("#acctTable").innerHTML = head + `<tbody>${body}</tbody>`;
  $$("#acctTable [data-suspend]").forEach((b) => b.onclick = () => suspendUser(b.dataset.suspend, b.dataset.to === "1"));
  $$("#acctTable [data-del]").forEach((b) => b.onclick = () => deleteUser(b.dataset.del, b.dataset.name));
}
async function suspendUser(id, to) {
  const r = await api(`/api/admin/users/${id}/suspend`, { method: "POST", body: { suspended: to } });
  if (!r.ok) return toast(r.data.error || "failed", "bad");
  toast(to ? "account suspended" : "account restored");
  loadAccounts();
}
async function deleteUser(id, name) {
  if (!confirm(`Delete ${name} and every message it holds? This cannot be undone.`)) return;
  const r = await api(`/api/admin/users/${id}`, { method: "DELETE" });
  if (!r.ok) return toast(r.data.error || "failed", "bad");
  toast("account deleted");
  loadAccounts();
}
let boxes = [], curBox = null, curMsgs = [];
async function loadSupport() {
  const r = await api("/api/mail/addresses");
  if (!r.ok) return toast(r.data.error || "failed to load mailboxes", "bad");
  boxes = r.data.addresses || [];
  const dom = r.data.domain;
  $("#supportBoxes").innerHTML = boxes.length ? boxes.map((a) => `<button class="support-box" data-box="${a.id}">${esc(a.local_part)}<span class="mono support-box__dom">@${esc(dom)}</span></button>`).join("") : '<span class="mono muted">no mailboxes on this account</span>';
  $$("#supportBoxes .support-box").forEach((b) => b.onclick = () => openBox(Number(b.dataset.box)));
  const pick = boxes.find((a) => a.local_part === "support") || boxes[0];
  if (pick) openBox(pick.id);
}
async function openBox(id) {
  curBox = id;
  $$("#supportBoxes .support-box").forEach((b) => b.classList.toggle("is-active", Number(b.dataset.box) === id));
  $("#supportReader").hidden = true;
  $("#supBox").textContent = (boxes.find((a) => a.id === id) || {}).local_part || "";
  const r = await api(`/api/mail/inbox/${id}`);
  if (!r.ok) return toast(r.data.error || "failed to load mail", "bad");
  curMsgs = (r.data.messages || []).filter((m) => m.direction === "in");
  renderSupportList();
}
function renderSupportList() {
  if (!curMsgs.length) {
    $("#supportList").innerHTML = '<li class="support-empty mono">nothing in this mailbox</li>';
    return;
  }
  $("#supportList").innerHTML = curMsgs.map((m, i) => `
    <li class="support-row ${m.is_read ? "" : "is-unread"}" data-i="${i}">
      <span class="support-row__from">${esc(m.from_addr)}</span>
      <span class="support-row__subj">${esc(m.subject || "(no subject)")}</span>
      <span class="support-row__date mono">${fmtDate(m.received_at)}</span>
    </li>`).join("");
  $$("#supportList .support-row").forEach((row) => row.onclick = () => openMsg(Number(row.dataset.i)));
}
function openMsg(i) {
  const m = curMsgs[i];
  if (!m) return;
  const label = (boxes.find((a) => a.id === curBox) || {}).local_part || "";
  const reader = $("#supportReader");
  reader.hidden = false;
  reader.innerHTML = `
    <div class="support-reader__subj">${esc(m.subject || "(no subject)")}</div>
    <div class="mono muted support-reader__meta">from ${esc(m.from_addr)} \xB7 ${fmtDate(m.received_at)}</div>
    <pre class="support-reader__body">${esc(m.body || "")}</pre>
    <form class="support-reply" id="supReply">
      <textarea class="input" id="supReplyBody" rows="4" placeholder="Write a reply\u2026" spellcheck="true"></textarea>
      <div class="support-reply__foot">
        <span class="mono muted">reply as ${esc(label)}</span>
        <button class="btn btn--primary btn--sm" type="submit">Send reply</button>
      </div>
    </form>`;
  if (!m.is_read) {
    api(`/api/mail/read/${m.id}`, { method: "POST" });
    m.is_read = 1;
  }
  $("#supReply").onsubmit = (e) => {
    e.preventDefault();
    sendReply(m);
  };
}
async function sendReply(m) {
  const body = $("#supReplyBody").value.trim();
  if (!body) return;
  const subject = /^re:/i.test(m.subject || "") ? m.subject : "Re: " + (m.subject || "");
  const btn = $("#supReply button");
  btn.disabled = true;
  const r = await api("/api/mail/send", { method: "POST", body: { addressId: curBox, to: m.from_addr, subject, body } });
  btn.disabled = false;
  if (!r.ok) return toast(r.data.error || "send failed", "bad");
  toast("reply sent");
  $("#supReplyBody").value = "";
}
async function loadReserved() {
  const r = await api("/api/admin/reserved");
  if (!r.ok) return toast(r.data.error || "failed", "bad");
  $("#reservedCustom").innerHTML = r.data.custom.length ? r.data.custom.map((n) => `<span class="chip">${esc(n)}<button class="chip__x" data-rm="${esc(n)}" aria-label="remove ${esc(n)}">\xD7</button></span>`).join("") : '<span class="mono muted">none added yet</span>';
  $("#reservedBuiltin").innerHTML = r.data.builtin.map((n) => `<span class="chip chip--static">${esc(n)}</span>`).join("");
  $$("#reservedCustom [data-rm]").forEach((b) => b.onclick = () => rmReserved(b.dataset.rm));
}
async function rmReserved(name) {
  const r = await api(`/api/admin/reserved/${encodeURIComponent(name)}`, { method: "DELETE" });
  if (!r.ok) return toast(r.data.error || "failed", "bad");
  loadReserved();
}
const loaders = { health: loadHealth, accounts: loadAccounts, support: loadSupport, reserved: loadReserved };
const loaded = new Set();
function showTab(name) {
  $$(".admin-tab").forEach((t) => t.classList.toggle("is-active", t.dataset.tab === name));
  $$(".admin-view").forEach((v) => {
    const on = v.dataset.view === name;
    v.hidden = !on;
    v.classList.toggle("is-active", on);
  });
  if (!loaded.has(name)) {
    loaded.add(name);
    loaders[name]();
  }
}
function wire() {
  $$(".admin-tab").forEach((t) => t.onclick = () => showTab(t.dataset.tab));
  $("#refreshStats").onclick = loadHealth;
  $("#logoutBtn").onclick = async () => {
    await api("/api/logout", { method: "POST" });
    location.href = "login";
  };
  $("#reservedAdd").onsubmit = async (e) => {
    e.preventDefault();
    const name = $("#reservedInput").value.trim().toLowerCase();
    if (!name) return;
    const r = await api("/api/admin/reserved", { method: "POST", body: { name } });
    if (!r.ok) return toast(r.data.error || "failed", "bad");
    $("#reservedInput").value = "";
    loadReserved();
  };
}
function denied() {
  $("#gateCard").innerHTML = `
    <span class="mono admin-gate__msg">Not authorized</span>
    <p class="admin-gate__sub">This area is for operators only.</p>
    <a class="btn btn--primary btn--sm" href="dashboard">Back to your inbox</a>`;
}
async function boot() {
  const r = await api("/api/me");
  if (!r.ok) {
    location.href = "login";
    return;
  }
  setCsrf(r.data.csrf);
  myId = r.data.user.id;
  if (!r.data.isAdmin) {
    denied();
    return;
  }
  $("#gate").hidden = true;
  $("#panel").hidden = false;
  wire();
  showTab("health");
}
boot();
