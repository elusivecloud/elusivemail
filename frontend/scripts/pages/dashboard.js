import {
  $,
  element as el,
  esc,
  icon,
  toast,
  undoToast,
  contextMenu,
  mountThemeToggles,
  setLoading
} from "../shared/ui.js";
import { api, setCsrf } from "../shared/api.js";
import {
  ensureUnlocked,
  decryptAll,
  verifyFingerprint,
  getPrivKey,
  clearSession,
  ensurePrekeys,
  resolveKey,
  pageShield
} from "../shared/crypto-session.js";
let me = null, domain = "", masterLimit = 5, encMode = "auto";
let myEncPrivateKey = null, myPublicKey = null;
let addresses = [], groups = [], folders = [], msgs = [];
let filterId = null;
let filterGroup = null;
let filterFolder = null;
let direction = "in";
let cursor = -1, openMsgId = null;
let query = "";
let composeAtts = [];
let pendingBurn = false;
let editingGroupId = null, editingFolderId = null;
const collapsedGroups = new Set();
function inlineEdit(container, { value, placeholder, onSave, onCancel }) {
  container.innerHTML = "";
  const input = el("input", { class: "input input--inline mono", value, placeholder });
  container.appendChild(input);
  input.focus();
  input.select();
  let done = false;
  const finish = (save) => {
    if (done) return;
    done = true;
    const v = input.value.trim();
    if (save && v) onSave(v);
    else onCancel?.();
  };
  input.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Enter") finish(true);
    else if (e.key === "Escape") finish(false);
  });
  input.addEventListener("blur", () => finish(true));
  input.addEventListener("click", (e) => e.stopPropagation());
}
const app = $("#app");
const initials = (s) => (s || "?").trim().slice(0, 2).toUpperCase();
function when(ts) {
  const d = new Date(ts), diff = Date.now() - ts;
  if (diff < 36e5) return `${Math.max(1, Math.floor(diff / 6e4))}m`;
  if (d.toDateString() === (new Date()).toDateString()) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (diff < 31536e6) return d.toLocaleDateString([], { month: "short", day: "numeric" });
  return d.toLocaleDateString([], { month: "short", year: "2-digit" });
}
function ttlLabel(expiresAt) {
  if (!expiresAt) return "";
  const ms = expiresAt - Date.now();
  if (ms <= 0) return "expired";
  const m = Math.floor(ms / 6e4);
  if (m < 60) return `${m}m`;
  if (m < 1440) return `${Math.floor(m / 60)}h`;
  return `${Math.floor(m / 1440)}d`;
}
function download(name, text) {
  const a = el("a", { href: URL.createObjectURL(new Blob([text], { type: "application/pgp-keys" })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}
const encLabel = (m) => m === "keyfile" ? "End-to-end, keyfile" : m === "private" ? "End-to-end" : "Encrypted at rest";
const addrById = (id) => addresses.find((a) => a.id === id);
const groupById = (id) => groups.find((g) => g.id === id);
const folderById = (id) => folders.find((f) => f.id === id);
const masters = () => addresses.filter((a) => !a.is_temp);
const burners = () => addresses.filter((a) => a.is_temp);
const addrsInGroup = (gid) => addresses.filter((a) => a.group_id === gid);
const ungrouped = () => addresses.filter((a) => !a.group_id);
const matches = (m) => {
  if (filterFolder === "junk") return !!m.is_junk;
  if (filterFolder != null) return m.folder_id === filterFolder;
  if (filterId) return m.addressId === filterId;
  if (filterGroup) return addrById(m.addressId)?.group_id === filterGroup;
  return true;
};
const matchesQuery = (m) => {
  if (!query) return true;
  const q = query.toLowerCase();
  return [m.subject, m.from_addr, m.to_addr, m.body].some((f) => (f || "").toLowerCase().includes(q));
};
const visible = () => msgs.filter((m) => m.direction === direction && matches(m) && matchesQuery(m));
const unreadFor = (id) => msgs.filter((m) => m.direction === "in" && !m.is_read && (!id || m.addressId === id)).length;
const unreadForGroup = (gid) => msgs.filter((m) => m.direction === "in" && !m.is_read && addrById(m.addressId)?.group_id === gid).length;
const unreadJunk = () => msgs.filter((m) => m.direction === "in" && !m.is_read && m.is_junk).length;
const unreadForFolder = (fid) => msgs.filter((m) => m.direction === "in" && !m.is_read && m.folder_id === fid).length;
async function boot() {
  pageShield();
  const { ok, data } = await api("/api/me");
  if (!ok) {
    location.href = "login";
    return;
  }
  me = data.user;
  domain = data.domain;
  masterLimit = data.masterLimit || 5;
  encMode = data.encMode || "auto";
  myEncPrivateKey = data.encPrivateKey;
  myPublicKey = data.publicKey;
  setCsrf(data.csrf);
  if (data.onboarded && !localStorage.getItem("elusive_update_seen")) {
    location.replace("updates");
    return;
  }
  if (!data.onboarded) localStorage.setItem("elusive_update_seen", "1");
  paintIdentity();
  if (!data.onboarded) {
    await runOnboarding();
  } else if (encMode !== "auto") {
    await verifyFingerprint(myPublicKey, me.username);
    await ensureUnlocked(myEncPrivateKey);
    ensurePrekeys(myPublicKey);
  }
  renderSkeleton();
  await refresh();
  wireEvents();
  setInterval(refresh, 6e4);
  let lastActive = Date.now();
  setInterval(checkIdentity, 12e4);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") lastActive = Date.now();
    else {
      if (Date.now() - lastActive > 12e4) checkIdentity();
      lastActive = Date.now();
    }
  });
  window.addEventListener("focus", () => {
    if (Date.now() - lastActive > 12e4) checkIdentity();
    lastActive = Date.now();
  });
}
async function checkIdentity() {
  const { ok, data } = await api("/api/me");
  if (!ok) {
    location.href = "login";
    return;
  }
  if (data.user.id !== me.id) {
    toast("Signed in as a different account in this browser. Reloading\u2026", { icon: "alert", timeout: 2200 });
    setTimeout(() => location.reload(), 900);
  }
}
function paintIdentity() {
  const ini = initials(me.nickname || me.username);
  $("#avatarInitials").textContent = ini;
  $("#menuAvatar").textContent = ini;
  $("#menuName").textContent = me.nickname || me.username;
  $("#menuMail").textContent = `${me.username}@${domain}`;
  $("#menuNote").textContent = encLabel(encMode);
}
async function refresh() {
  const [{ data }, { data: folderData }] = await Promise.all([
    api("/api/mail/addresses"),
    api("/api/folders")
  ]);
  addresses = data.addresses || [];
  groups = data.groups || [];
  folders = folderData.folders || [];
  domain = data.domain || domain;
  if (filterId && !addresses.some((a) => a.id === filterId)) filterId = null;
  if (filterGroup && !groups.some((g) => g.id === filterGroup)) filterGroup = null;
  if (typeof filterFolder === "number" && !folders.some((f) => f.id === filterFolder)) filterFolder = null;
  const inboxes = await Promise.all(addresses.map(
    (a) => api(`/api/mail/inbox/${a.id}`).then((r) => (r.data.messages || []).map((m) => ({ ...m, addressId: a.id })))
  ));
  msgs = inboxes.flat().sort((a, b) => b.received_at - a.received_at);
  await decryptAll(msgs);
  render();
}
function render() {
  renderSidebar();
  renderList();
}
function renderSidebar() {
  const all = $("#allMailItem");
  all.classList.toggle("active", filterId === null && filterGroup === null && filterFolder === null);
  all.dataset.dropKind = "group";
  all.dataset.dropGroup = "";
  const au = unreadFor(null);
  const auBadge = $("#allUnread");
  auBadge.hidden = !au;
  auBadge.textContent = au;
  const junk = $("#junkItem");
  junk.classList.toggle("active", filterFolder === "junk");
  junk.dataset.dropKind = "junk";
  const ju = unreadJunk();
  const junkBadge = $("#junkUnread");
  junkBadge.hidden = !ju;
  junkBadge.textContent = ju;
  const folderTree = $("#folderTree");
  folderTree.innerHTML = "";
  for (const f of folders) folderTree.appendChild(folderItem(f));
  const tree = $("#sideTree");
  tree.innerHTML = "";
  for (const g of groups) tree.appendChild(groupSection(g));
  const solo = ungrouped();
  if (groups.length && solo.length) tree.appendChild(el("div", { class: "side-group__label side-sub", html: "<span>No persona</span>" }));
  for (const a of solo) tree.appendChild(sideItem(a));
  if (!addresses.length) tree.appendChild(el("div", { class: "side-empty", text: "No addresses yet. Use the + above." }));
}
function folderItem(f) {
  const editing = editingFolderId === f.id;
  const node = el(editing ? "div" : "button", { class: "side-item" + (filterFolder === f.id ? " active" : ""), dataset: { dropKind: "folder", dropFolder: String(f.id) } });
  const unread = unreadForFolder(f.id);
  node.innerHTML = `
    <span class="side-item__icon">${icon("folder", { size: 15 })}</span>
    <span class="side-item__label"></span>
    ${!editing && unread ? `<span class="side-item__badge">${unread}</span>` : ""}`;
  const labelEl = node.querySelector(".side-item__label");
  if (editing) {
    inlineEdit(labelEl, {
      value: f.name,
      placeholder: "Folder name",
      onSave: async (v) => {
        editingFolderId = null;
        await api(`/api/folders/${f.id}`, { method: "PATCH", body: { name: v } });
        await refresh();
      },
      onCancel: () => {
        editingFolderId = null;
        renderSidebar();
      }
    });
  } else {
    labelEl.textContent = f.name;
    node.addEventListener("click", () => {
      filterFolder = f.id;
      filterId = null;
      filterGroup = null;
      cursor = -1;
      closeSidebar();
      render();
    });
    node.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      contextMenu(e.clientX, e.clientY, [[
        { label: "Rename folder", onClick: () => {
          editingFolderId = f.id;
          renderSidebar();
        } },
        { label: "Delete folder", danger: true, onClick: () => deleteFolder(f) }
      ]]);
    });
  }
  return node;
}
function groupSection(g) {
  const wrap = el("div", { class: "side-persona" });
  const collapsed = collapsedGroups.has(g.id);
  const unread = unreadForGroup(g.id);
  const editing = editingGroupId === g.id;
  const head = el(editing ? "div" : "button", { class: "side-persona__head" + (filterGroup === g.id ? " active" : ""), dataset: { dropKind: "group", dropGroup: String(g.id) } });
  const swatch = g.color ? ` style="color:${esc(g.color)};background:color-mix(in srgb, ${esc(g.color)} 20%, transparent)"` : "";
  head.innerHTML = `
    <span class="side-persona__caret${collapsed ? "" : " open"}">${icon("chevronRight", { size: 14 })}</span>
    <span class="side-persona__icon"${swatch}>${icon("layers", { size: 15 })}</span>
    <span class="side-item__label"></span>
    ${!editing && unread ? `<span class="side-item__badge">${unread}</span>` : ""}`;
  head.querySelector(".side-persona__caret").addEventListener("click", (e) => {
    e.stopPropagation();
    collapsed ? collapsedGroups.delete(g.id) : collapsedGroups.add(g.id);
    renderSidebar();
  });
  const labelEl = head.querySelector(".side-item__label");
  if (editing) {
    inlineEdit(labelEl, {
      value: g.name,
      placeholder: "Persona name",
      onSave: async (v) => {
        editingGroupId = null;
        await api(`/api/groups/${g.id}`, { method: "PATCH", body: { name: v } });
        await refresh();
      },
      onCancel: () => {
        editingGroupId = null;
        renderSidebar();
      }
    });
  } else {
    labelEl.textContent = g.name;
    head.addEventListener("click", () => {
      filterGroup = g.id;
      filterId = null;
      filterFolder = null;
      cursor = -1;
      closeSidebar();
      render();
    });
    head.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      contextMenu(e.clientX, e.clientY, [[
        { label: "Rename persona", onClick: () => {
          editingGroupId = g.id;
          renderSidebar();
        } },
        { label: "Change color", onClick: () => recolorPersona(g, head.querySelector(".side-persona__icon")) },
        { label: "Delete persona", danger: true, onClick: () => deletePersona(g) }
      ]]);
    });
  }
  wrap.appendChild(head);
  if (!collapsed) {
    const kids = el("div", { class: "side-persona__kids" });
    const list = addrsInGroup(g.id);
    if (!list.length) kids.appendChild(el("div", { class: "side-empty", text: "Empty. Drag an address here." }));
    for (const a of list) kids.appendChild(sideItem(a));
    wrap.appendChild(kids);
  }
  return wrap;
}
function sideItem(a) {
  const temp = !!a.is_temp;
  const node = el("button", { class: "side-item side-item--addr" + (filterId === a.id ? " active" : "") });
  const unread = unreadFor(a.id);
  const ic = a.burn_on_read ? "flame" : temp ? "clock" : "at";
  node.innerHTML = `
    <span class="side-item__icon">${icon(ic, { size: 15 })}</span>
    <span class="side-item__label mono">${esc(a.local_part)}</span>
    ${a.burn_on_read ? `<span class="side-item__ttl burn">burn</span>` : temp && a.expires_at ? `<span class="side-item__ttl">${ttlLabel(a.expires_at)}</span>` : ""}
    ${unread ? `<span class="side-item__badge">${unread}</span>` : ""}`;
  node.addEventListener("click", () => {
    filterId = a.id;
    filterGroup = null;
    filterFolder = null;
    cursor = -1;
    closeSidebar();
    render();
  });
  node.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    contextMenu(e.clientX, e.clientY, [
      [{ label: "Copy address", onClick: () => {
        navigator.clipboard.writeText(`${a.local_part}@${domain}`);
        toast("Address copied");
      } }],
      [
        { label: "No persona", onClick: () => moveAddressToGroup(a.id, null) },
        ...groups.map((g) => ({ label: g.name, onClick: () => moveAddressToGroup(a.id, g.id) }))
      ],
      [{ label: temp ? "Burn now" : "Delete address", danger: true, onClick: () => deleteAddress(a) }]
    ]);
  });
  wireDrag(node, {
    threshold: 6,
    label: `${a.local_part}@${domain}`,
    acceptKinds: ["group"],
    onDrop: (target) => {
      if (!target) return;
      const gid = target.dataset.dropGroup;
      moveAddressToGroup(a.id, gid === "" ? null : Number(gid));
    }
  });
  return node;
}
function renderSkeleton() {
  const list = $("#mlist");
  list.innerHTML = "";
  for (let i = 0; i < 6; i++) {
    const s = el("div", { class: "mrow-skel" });
    s.innerHTML = `<div class="skeleton skeleton--line" style="width:${40 + Math.random() * 30}%"></div>
      <div class="skeleton skeleton--line" style="width:${70 + Math.random() * 20}%;height:9px"></div>`;
    list.appendChild(s);
  }
}
function renderList() {
  $("#listTitle").textContent = filterId ? addrById(filterId)?.local_part || "" : filterGroup ? groupById(filterGroup)?.name || "" : filterFolder === "junk" ? "Junk" : filterFolder != null ? folderById(filterFolder)?.name || "" : "All mail";
  const rows = visible();
  $("#listCount").textContent = rows.length ? `${rows.length}` : "";
  const list = $("#mlist");
  list.innerHTML = "";
  if (!rows.length) {
    list.appendChild(emptyList());
    return;
  }
  rows.forEach((m, i) => {
    const a = addrById(m.addressId);
    const who = direction === "in" ? m.from_addr : m.to_addr;
    const row = el("div", {
      class: "mrow" + (direction === "in" && !m.is_read ? " unread" : "") + (i === cursor ? " cursor" : "") + (m.id === openMsgId ? " active" : "")
    });
    row.innerHTML = `
      <div class="mrow__top">
        ${direction === "in" && !m.is_read ? '<span class="mrow__dot"></span>' : ""}
        <span class="mrow__who">${esc(who) || "unknown"}</span>
        ${!filterId && a ? `<span class="mrow__alias">${esc(a.local_part)}</span>` : ""}
      </div>
      <span class="mrow__time">${when(m.received_at)}</span>
      <span class="mrow__subject">${esc(m.subject) || "(no subject)"}</span>`;
    row.addEventListener("click", () => {
      cursor = i;
      openMessage(m);
    });
    row.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      lastCtxX = e.clientX;
      lastCtxY = e.clientY;
      contextMenu(e.clientX, e.clientY, messageMenu(m));
    });
    const tools = el("div", { class: "mrow__tools" });
    for (const act of ROW_ACTIONS) {
      if (!rowTools.includes(act.id) || act.inboxOnly && direction !== "in") continue;
      const tip = act.tip(m);
      const b = el("button", { class: "mrow__tool" + (act.danger ? " danger" : ""), "data-tooltip": tip, "aria-label": tip });
      b.innerHTML = icon(act.icon, { size: 15 });
      b.addEventListener("click", (e) => {
        e.stopPropagation();
        act.run(m);
      });
      tools.appendChild(b);
    }
    tools.addEventListener("pointerdown", (e) => e.stopPropagation());
    tools.addEventListener("click", (e) => e.stopPropagation());
    tools.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      e.stopPropagation();
      customizeToolbar(e.clientX, e.clientY);
    });
    if (tools.childElementCount) row.appendChild(tools);
    wireDrag(row, {
      threshold: 6,
      label: m.subject || "(no subject)",
      acceptKinds: ["folder", "junk"],
      onDrop: (target) => {
        if (!target) return;
        if (target.dataset.dropKind === "junk") setJunk(m, true);
        else moveMessageToFolder(m, Number(target.dataset.dropFolder));
      }
    });
    list.appendChild(row);
  });
}
function emptyList() {
  const e = el("div", { class: "empty" });
  if (query) {
    e.innerHTML = `
      <div class="empty__art">${icon("inbox", { size: 26 })}</div>
      <div class="empty__title">No matches</div>
      <p>Nothing here matches &ldquo;${esc(query)}&rdquo;.</p>`;
    return e;
  }
  e.innerHTML = `
    <div class="empty__art">${icon(direction === "in" ? "inbox" : "send", { size: 26 })}</div>
    <div class="empty__title">${direction === "in" ? "Nothing here" : "Nothing sent yet"}</div>
    <p>${direction === "in" ? "Quiet is the point. New mail lands here." : "Messages you send will show up here."}</p>`;
  return e;
}
const reader = $("#reader");
function openReader() {
  app.classList.add("reader-open");
}
function closeReader() {
  app.classList.remove("reader-open");
  openMsgId = null;
  reader.innerHTML = readerEmpty();
  renderList();
  if (pendingBurn) {
    pendingBurn = false;
    refresh();
  }
}
function readerEmpty() {
  return `<div class="reader-empty">
    <div class="empty__title">Select a message</div>
    <p>Pick something from the list, or start a new message.</p>
  </div>`;
}
const CLIP = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8.5 12.5 17a4 4 0 0 1-5.7-5.7l8-8a2.6 2.6 0 0 1 3.7 3.7l-8 8a1.2 1.2 0 0 1-1.7-1.7l7.3-7.3"/></svg>';
function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return Math.round(n / 1024) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}
function attChips(atts) {
  if (!atts || !atts.length) return "";
  return `<div class="reader__atts">${atts.map((at) => `<button class="att-chip" data-att="${at.id}" data-name="${esc(at.filename)}">${CLIP}<span class="att-chip__name">${esc(at.filename)}</span><span class="att-chip__size">${fmtSize(at.size)}</span></button>`).join("")}</div>`;
}
async function downloadAttachment(id, filename) {
  try {
    const res = await fetch(`/api/mail/attachment/${id}`);
    if (!res.ok) {
      toast("Could not fetch that attachment", { icon: "alert" });
      return;
    }
    let bytes;
    const contentType = res.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      const env = await res.json();
      if (!env.encKey) {
        toast("Could not fetch that attachment", { icon: "alert" });
        return;
      }
      if (!getPrivKey()) {
        toast("Unlock your mail first", { icon: "alert" });
        return;
      }
      const key = await resolveKey(env.encKey);
      const cipher = Uint8Array.from(atob(env.data), (c) => c.charCodeAt(0));
      bytes = await ElusiveCrypto.decryptAttachment(key, cipher);
    } else {
      bytes = new Uint8Array(await res.arrayBuffer());
    }
    const url = URL.createObjectURL(new Blob([bytes]));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || "attachment";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5e3);
  } catch {
    toast("Could not open that attachment", { icon: "alert" });
  }
}
function fileToB64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1]);
    r.onerror = reject;
    r.readAsDataURL(file);
  });
}
function renderComposeAtts() {
  const host = $("#cAtts");
  if (!host) return;
  host.innerHTML = composeAtts.map((a, i) => `<span class="att-chip att-chip--compose">${CLIP}<span class="att-chip__name">${esc(a.filename)}</span><span class="att-chip__size">${fmtSize(a.size)}</span><button class="att-chip__x" data-i="${i}" aria-label="Remove">${icon("close", { size: 13 })}</button></span>`).join("");
  host.querySelectorAll(".att-chip__x").forEach((b) => b.addEventListener("click", () => {
    composeAtts.splice(Number(b.dataset.i), 1);
    renderComposeAtts();
  }));
}
function quoteBody(m, mine) {
  const who = m.direction === "in" ? m.from_addr || "unknown" : mine;
  const when2 = new Date(m.received_at).toLocaleString();
  const quoted = (m.body || "").split("\n").map((l) => `> ${l}`).join("\n");
  return `

On ${when2}, ${who} wrote:
${quoted}`;
}
const rePrefix = (s) => /^re:/i.test(s || "") ? s : `Re: ${s || ""}`;
const fwdPrefix = (s) => /^fwd?:/i.test(s || "") ? s : `Fwd: ${s || ""}`;
function replyTo(m) {
  const a = addrById(m.addressId);
  const mine = a ? `${a.local_part}@${domain}` : "";
  openCompose({
    to: m.direction === "in" ? m.from_addr : m.to_addr,
    subject: rePrefix(m.subject),
    addressId: m.addressId,
    body: quoteBody(m, mine)
  });
}
function forwardMsg(m) {
  openCompose({
    subject: fwdPrefix(m.subject),
    addressId: m.addressId,
    body: `

---------- Forwarded message ----------
From: ${m.from_addr || "unknown"}
Date: ${new Date(m.received_at).toLocaleString()}
Subject: ${m.subject || ""}

${m.body || ""}`
  });
}
function linkify(s) {
  const re = /\bhttps?:\/\/[^\s<>"']+/g;
  let out = "";
  let last = 0;
  let m;
  while ((m = re.exec(s)) !== null) {
    out += esc(s.slice(last, m.index));
    const url = m[0];
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = url;
    out += a.outerHTML;
    last = m.index + url.length;
  }
  out += esc(s.slice(last));
  return out;
}
async function setRead(m, isRead) {
  m.is_read = isRead ? 1 : 0;
  renderSidebar();
  renderList();
  const { ok, data } = await api(`/api/mail/message/${m.id}`, { method: "PATCH", body: { isRead } });
  if (!ok) {
    toast(data.error || "Could not update.", { icon: "alert" });
    refresh();
  }
}
const ROW_ACTIONS = [
  { id: "read", name: "Read / unread", icon: "mailOpen", inboxOnly: true, tip: (m) => m.is_read ? "Mark unread" : "Mark read", run: (m) => setRead(m, !m.is_read) },
  { id: "reply", name: "Reply", icon: "reply", tip: () => "Reply", run: replyTo },
  { id: "forward", name: "Forward", icon: "forward", tip: () => "Forward", run: forwardMsg },
  { id: "junk", name: "Junk", icon: "ban", inboxOnly: true, tip: (m) => m.is_junk ? "Not junk" : "Mark as junk", run: (m) => setJunk(m, !m.is_junk) },
  { id: "trash", name: "Delete", icon: "trash", danger: true, tip: () => "Delete", run: deleteMessage }
];
const TOOLS_KEY = "elusive_row_tools";
let rowTools = (() => {
  try {
    const v = JSON.parse(localStorage.getItem(TOOLS_KEY));
    if (Array.isArray(v)) return v;
  } catch {
  }
  return ["read", "junk", "trash"];
})();
function customizeToolbar(x, y) {
  contextMenu(x, y, [ROW_ACTIONS.map((a) => ({
    label: a.name,
    checked: rowTools.includes(a.id),
    onClick: () => {
      rowTools = rowTools.includes(a.id) ? rowTools.filter((t) => t !== a.id) : ROW_ACTIONS.filter((x2) => rowTools.includes(x2.id) || x2.id === a.id).map((x2) => x2.id);
      try {
        localStorage.setItem(TOOLS_KEY, JSON.stringify(rowTools));
      } catch {
      }
      renderList();
      customizeToolbar(x, y);
    }
  }))]);
}
function messageMenu(m) {
  const inbox = m.direction === "in";
  return [
    [
      { label: "Open", icon: "mail", onClick: () => openMessage(m) },
      ...m.locked ? [] : [
        { label: "Reply", icon: "reply", onClick: () => replyTo(m) },
        { label: "Forward", icon: "forward", onClick: () => forwardMsg(m) }
      ]
    ],
    [
      ...inbox ? [{ label: m.is_read ? "Mark as unread" : "Mark as read", icon: "mailOpen", onClick: () => setRead(m, !m.is_read) }] : [],
      {
        label: inbox ? "Copy sender address" : "Copy recipient address",
        icon: "copy",
        onClick: () => {
          navigator.clipboard.writeText((inbox ? m.from_addr : m.to_addr) || "");
          toast("Address copied");
        }
      },
      ...inbox ? [{ label: m.is_junk ? "Not junk" : "Mark as junk", icon: "ban", onClick: () => setJunk(m, !m.is_junk) }] : []
    ],
    [
      ...m.folder_id ? [{ label: "Remove from folder", icon: "folder", onClick: () => moveMessageToFolder(m, null) }] : [],
      ...folders.filter((f) => f.id !== m.folder_id).map((f) => ({ label: `Move to \u201C${f.name}\u201D`, icon: "folder", onClick: () => moveMessageToFolder(m, f.id) }))
    ],
    [{ label: "Customize quick actions", icon: "sliders", onClick: () => customizeToolbar(lastCtxX, lastCtxY) }],
    [{ label: "Delete", icon: "trash", danger: true, onClick: () => deleteMessage(m) }]
  ];
}
let lastCtxX = 0, lastCtxY = 0;
async function openMessage(m) {
  openMsgId = m.id;
  const a = addrById(m.addressId);
  const willBurn = !!(a && a.burn_on_read && m.direction === "in");
  if (m.direction === "in" && !m.is_read) {
    const r = await api(`/api/mail/read/${m.id}`, { body: {} });
    m.is_read = 1;
    if (willBurn || r.data?.burned) pendingBurn = true;
  } else if (willBurn) {
    pendingBurn = true;
  }
  renderSidebar();
  renderList();
  const mine = a ? `${a.local_part}@${domain}` : "";
  const route = m.direction === "in" ? `<span class="reader__from">${esc(m.from_addr) || "unknown"}</span> <span class="text-subtle">to</span> <span class="reader__to">${esc(mine)}</span>` : `<span class="reader__from">${esc(mine)}</span> <span class="text-subtle">to</span> <span class="reader__to">${esc(m.to_addr)}</span>`;
  reader.innerHTML = `
    <div class="reader">
      <div class="reader__bar">
        <button class="btn btn--icon btn--ghost reader__bar-back" id="readerBack" aria-label="Back">${icon("arrowLeft", { size: 18 })}</button>
        <span class="reader__bar-spacer"></span>
        ${m.locked ? "" : `<button class="btn btn--icon btn--ghost" id="replyBtn" data-tooltip="Reply">${icon("reply", { size: 18 })}</button>
        <button class="btn btn--icon btn--ghost" id="fwdBtn" data-tooltip="Forward">${icon("forward", { size: 18 })}</button>`}
        ${m.direction === "in" && !willBurn ? `<button class="btn btn--icon btn--ghost" id="junkBtn" data-tooltip="${m.is_junk ? "Not junk" : "Mark as junk"}">${icon("ban", { size: 18 })}</button>` : ""}
        <button class="btn btn--icon btn--ghost" id="delBtn" data-tooltip="Delete">${icon("trash", { size: 18 })}</button>
        <button class="btn btn--icon btn--ghost reader__bar-back" id="readerClose" aria-label="Close">${icon("close", { size: 18 })}</button>
      </div>
      <div class="reader__body-wrap">
        <h1 class="reader__subject">${esc(m.subject) || "(no subject)"}</h1>
        <div class="reader__meta">
          <div class="reader__route">
            <span class="avatar avatar--sm reader__avatar">${initials(m.direction === "in" ? m.from_addr : mine)}</span>
            <span>${route}</span>
          </div>
          <div class="reader__tags">
            <span class="reader__time">${new Date(m.received_at).toLocaleString()}</span>
            <span class="badge badge--dot">${encMode === "auto" ? "encrypted at rest" : "end-to-end"}</span>
          </div>
        </div>
        ${willBurn ? `<div class="reader-burn">${icon("flame", { size: 18 })}<span>Seen once. This alias and its mail burn the moment you close this message.</span></div>` : ""}
        <div class="reader__body">${m.locked ? '<span class="text-muted">This message could not be decrypted with your current key.</span>' : linkify(m.body) || '<span class="text-muted">(no content)</span>'}</div>
        ${m.locked ? "" : attChips(m.attachments)}
      </div>
    </div>`;
  $("#readerBack")?.addEventListener("click", closeReader);
  $("#readerClose")?.addEventListener("click", closeReader);
  $("#delBtn")?.addEventListener("click", () => deleteMessage(m));
  $("#replyBtn")?.addEventListener("click", () => replyTo(m));
  $("#fwdBtn")?.addEventListener("click", () => forwardMsg(m));
  $("#junkBtn")?.addEventListener("click", async () => {
    await setJunk(m, !m.is_junk);
    closeReader();
  });
  reader.querySelectorAll(".att-chip").forEach((c) => c.addEventListener("click", () => downloadAttachment(Number(c.dataset.att), c.dataset.name)));
  openReader();
}
function deleteMessage(m) {
  msgs = msgs.filter((x) => x.id !== m.id);
  closeReader();
  undoToast("Message deleted", {
    onExpire: () => api(`/api/mail/message/${m.id}`, { method: "DELETE" }),
    onUndo: () => refresh()
  });
}
function openCompose(prefill = {}) {
  composeAtts = [];
  const fromId = prefill.addressId || filterId || (masters()[0] || addresses[0] || {}).id;
  const options = addresses.map((a) => `<option value="${a.id}" ${a.id === fromId ? "selected" : ""}>${esc(a.local_part)}@${esc(domain)}</option>`).join("");
  reader.innerHTML = `
    <div class="compose">
      <div class="reader__bar">
        <button class="btn btn--icon btn--ghost reader__bar-back" id="composeBack" aria-label="Back">${icon("arrowLeft", { size: 18 })}</button>
        <span class="list-head__title">New message</span>
        <span class="reader__bar-spacer"></span>
        <button class="btn btn--icon btn--ghost" id="composeClose" aria-label="Discard">${icon("close", { size: 18 })}</button>
      </div>
      <form class="compose__form" id="composeForm">
        <div class="compose__row"><label for="cFrom">From</label><select class="select" id="cFrom">${options}</select></div>
        <div class="compose__row"><label for="cTo">To</label><input class="input" id="cTo" type="email" placeholder="recipient@example.com" autocomplete="off" value="${esc(prefill.to || "")}"></div>
        <div class="compose__row"><label for="cSubject">Subject</label><input class="input" id="cSubject" type="text" autocomplete="off" value="${esc(prefill.subject || "")}"></div>
        <textarea class="compose__body" id="cBody" placeholder="Write something.">${esc(prefill.body || "")}</textarea>
        <div class="compose__atts" id="cAtts"></div>
      </form>
      <div class="compose__foot">
        <input type="file" id="cFile" multiple hidden>
        <button class="btn btn--secondary" id="attachBtn">${CLIP} Attach</button>
        <button class="btn btn--primary" id="sendBtn">${icon("send", { size: 16 })} Send</button>
        <span class="compose__status" id="cStatus"></span>
      </div>
    </div>`;
  $("#composeBack").addEventListener("click", closeReader);
  $("#composeClose").addEventListener("click", closeReader);
  $("#sendBtn").addEventListener("click", sendMail);
  $("#attachBtn").addEventListener("click", () => $("#cFile").click());
  $("#cFile").addEventListener("change", async (e) => {
    for (const f of e.target.files) {
      if (f.size > 10 * 1024 * 1024) {
        toast(`${f.name} is over the 10 MB limit`, { icon: "alert" });
        continue;
      }
      composeAtts.push({ filename: f.name, mime: f.type || "application/octet-stream", size: f.size, content: await fileToB64(f) });
    }
    e.target.value = "";
    renderComposeAtts();
  });
  openReader();
  if (prefill.body) {
    const b = $("#cBody");
    b.focus();
    b.setSelectionRange(0, 0);
  } else ($("#cTo").value ? $("#cSubject") : $("#cTo")).focus();
}
async function sendMail() {
  const btn = $("#sendBtn"), status = $("#cStatus");
  const to = $("#cTo").value.trim(), subject = $("#cSubject").value.trim();
  if (!to) {
    status.textContent = "Add a recipient first.";
    return;
  }
  if (!subject) {
    status.textContent = "A subject helps. Add one.";
    return;
  }
  setLoading(btn, true);
  const { ok, data } = await api("/api/mail/send", { body: {
    addressId: Number($("#cFrom").value),
    to,
    subject,
    body: $("#cBody").value,
    attachments: composeAtts.map((a) => ({ filename: a.filename, mime: a.mime, content: a.content }))
  } });
  if (!ok) {
    setLoading(btn, false);
    status.textContent = data.error || "That didn't send.";
    return;
  }
  toast("Message sent", { icon: "send" });
  closeReader();
  refresh();
}
const WORDS = [
  "mist",
  "echo",
  "drift",
  "cinder",
  "vesper",
  "onyx",
  "fable",
  "lumen",
  "sable",
  "quiet",
  "raven",
  "ashen",
  "velvet",
  "ghost",
  "ember",
  "frost",
  "sombra",
  "noir",
  "static",
  "hollow"
];
const suggestName = () => WORDS[Math.floor(Math.random() * WORDS.length)] + "." + Math.random().toString(36).slice(2, 6);
async function createGroup() {
  const { ok, data } = await api("/api/groups", { body: { name: "New persona" } });
  if (!ok) {
    toast(data.error || "Could not create.", { icon: "alert" });
    return;
  }
  editingGroupId = data.group.id;
  await refresh();
}
const groupOptions = (selected) => `<option value="">No persona</option>` + groups.map((g) => `<option value="${g.id}" ${g.id === selected ? "selected" : ""}>${esc(g.name)}</option>`).join("");
function wireDrag(handle, { label, onDrop, threshold = 0, acceptKinds = null }) {
  handle.addEventListener("pointerdown", (e) => {
    if (e.button !== void 0 && e.button !== 0) return;
    const startX = e.clientX, startY = e.clientY;
    let started = false, ghost = null, lastTarget = null, finished = false, prevUserSelect = "";
    const place = (x, y) => {
      if (ghost) {
        ghost.style.left = x + 10 + "px";
        ghost.style.top = y + 10 + "px";
      }
    };
    const beginDrag = () => {
      started = true;
      handle.setPointerCapture(e.pointerId);
      prevUserSelect = document.body.style.userSelect;
      document.body.style.userSelect = "none";
      ghost = el("div", { class: "drag-ghost", text: typeof label === "function" ? label() : label });
      document.body.appendChild(ghost);
      place(e.clientX, e.clientY);
      handle.classList.add("is-dragging");
    };
    const findTarget = (x, y) => {
      if (ghost) ghost.style.display = "none";
      const under = document.elementFromPoint(x, y);
      if (ghost) ghost.style.display = "";
      const target = under && under.closest("[data-drop-kind]");
      if (!target) return null;
      if (acceptKinds && !acceptKinds.includes(target.dataset.dropKind)) return null;
      return target;
    };
    const onMove = (ev) => {
      if (!started) {
        if (Math.hypot(ev.clientX - startX, ev.clientY - startY) < threshold) return;
        e.preventDefault?.();
        beginDrag();
      }
      place(ev.clientX, ev.clientY);
      const target = findTarget(ev.clientX, ev.clientY);
      if (target !== lastTarget) {
        if (lastTarget) lastTarget.classList.remove("is-drop-target");
        if (target) target.classList.add("is-drop-target");
        lastTarget = target;
      }
    };
    const cleanup = () => {
      if (finished) return;
      finished = true;
      handle.removeEventListener("pointermove", onMove);
      handle.removeEventListener("pointerup", onUp);
      handle.removeEventListener("pointercancel", onCancel);
      if (started) {
        if (handle.hasPointerCapture(e.pointerId)) handle.releasePointerCapture(e.pointerId);
        document.body.style.userSelect = prevUserSelect;
        ghost?.remove();
        handle.classList.remove("is-dragging");
        if (lastTarget) lastTarget.classList.remove("is-drop-target");
      }
    };
    const onUp = () => {
      const wasStarted = started, target = lastTarget;
      cleanup();
      if (wasStarted) onDrop(target);
    };
    const onCancel = () => cleanup();
    handle.addEventListener("pointermove", onMove);
    handle.addEventListener("pointerup", onUp, { once: true });
    handle.addEventListener("pointercancel", onCancel, { once: true });
  });
}
async function moveAddressToGroup(addrId, groupId) {
  const { ok, data } = await api(`/api/mail/addresses/${addrId}`, { method: "PATCH", body: { groupId } });
  if (!ok) {
    toast(data.error || "Could not move.", { icon: "alert" });
    return;
  }
  toast("Moved");
  await refresh();
}
function recolorPersona(g, anchorEl) {
  const input = el("input", { type: "color", value: g.color || "#8a8f99", style: "position:fixed;opacity:0;pointer-events:none" });
  const box = anchorEl.getBoundingClientRect();
  input.style.left = box.left + "px";
  input.style.top = box.top + "px";
  document.body.appendChild(input);
  input.addEventListener("input", async () => {
    const { ok, data } = await api(`/api/groups/${g.id}`, { method: "PATCH", body: { color: input.value } });
    if (!ok) toast(data.error || "Could not recolor.", { icon: "alert" });
    else await refresh();
  });
  input.addEventListener("change", () => input.remove());
  input.click();
}
function deletePersona(g) {
  groups = groups.filter((x) => x.id !== g.id);
  if (filterGroup === g.id) filterGroup = null;
  render();
  undoToast(`Deleted \u201C${g.name}\u201D`, {
    onExpire: () => api(`/api/groups/${g.id}`, { method: "DELETE" }),
    onUndo: () => refresh()
  });
}
function deleteAddress(a) {
  const temp = !!a.is_temp;
  addresses = addresses.filter((x) => x.id !== a.id);
  if (filterId === a.id) filterId = null;
  render();
  undoToast(temp ? "Alias burned" : `Deleted ${a.local_part}@${domain}`, {
    onExpire: () => api(`/api/mail/addresses/${a.id}`, { method: "DELETE" }),
    onUndo: () => refresh()
  });
}
async function createFolder() {
  const { ok, data } = await api("/api/folders", { body: { name: "New folder" } });
  if (!ok) {
    toast(data.error || "Could not create.", { icon: "alert" });
    return;
  }
  editingFolderId = data.folder.id;
  await refresh();
}
function deleteFolder(f) {
  folders = folders.filter((x) => x.id !== f.id);
  if (filterFolder === f.id) filterFolder = null;
  render();
  undoToast(`Deleted \u201C${f.name}\u201D`, {
    onExpire: () => api(`/api/folders/${f.id}`, { method: "DELETE" }),
    onUndo: () => refresh()
  });
}
async function moveMessageToFolder(m, folderId) {
  const { ok, data } = await api(`/api/mail/message/${m.id}`, { method: "PATCH", body: { folderId } });
  if (!ok) {
    toast(data.error || "Could not move.", { icon: "alert" });
    return;
  }
  toast(folderId ? "Filed" : "Removed from folder");
  await refresh();
}
async function setJunk(m, isJunk) {
  const { ok, data } = await api(`/api/mail/message/${m.id}`, { method: "PATCH", body: { isJunk } });
  if (!ok) {
    toast(data.error || "Could not update.", { icon: "alert" });
    return;
  }
  toast(isJunk ? "Marked as junk" : "Not junk");
  await refresh();
}
function openAddressPopover(anchorEl) {
  document.querySelectorAll(".addr-pop").forEach((p) => p.remove());
  let creatingTemp = false, life = 60, burnOnRead = false;
  const mfull = masters().length >= masterLimit;
  const pop = el("div", { class: "addr-pop", role: "dialog", "aria-label": "New address" });
  pop.innerHTML = `
    <div class="mgr__seg"><div class="segment" id="typeSeg">
      <button data-temp="0" class="active" ${mfull ? "disabled" : ""}>Master</button>
      <button data-temp="1">Disposable</button>
    </div></div>
    <div class="mgr__input-row">
      <div class="input-affix input-affix--suffix">
        <input class="input mono" id="newLocal" placeholder="pick a name" autocomplete="off" spellcheck="false">
        <span class="affix">@${esc(domain)}</span>
      </div>
      <button class="btn btn--icon btn--secondary" id="diceBtn" data-tooltip="Suggest">${icon("dice", { size: 18 })}</button>
    </div>
    <div class="mgr__field" id="lifeRow" hidden>
      <span class="mgr__field-label">Lifespan</span>
      <div class="mgr__life" id="lifePresets">
        ${[[1, "1m"], [10, "10m"], [60, "1h"], [360, "6h"], [1440, "24h"]].map(([m, l]) => `<button data-min="${m}" class="${m === life ? "active" : ""}">${l}</button>`).join("")}
        <button data-burn="1" class="burn">Burn on read</button>
      </div>
    </div>
    <div class="mgr__field">
      <span class="mgr__field-label">Persona</span>
      <select class="select" id="newGroupSel">${groupOptions(null)}</select>
    </div>
    <div class="mgr__foot">
      <span class="mgr__err" id="addrErr"></span>
      <button class="btn btn--primary btn--sm" id="addrConfirm">Create</button>
    </div>`;
  document.body.appendChild(pop);
  const box = anchorEl.getBoundingClientRect();
  const popBox = pop.getBoundingClientRect();
  pop.style.left = Math.min(box.left, window.innerWidth - popBox.width - 12) + "px";
  pop.style.top = Math.min(box.bottom + 6, window.innerHeight - popBox.height - 12) + "px";
  const local = pop.querySelector("#newLocal");
  const lifeRow = pop.querySelector("#lifeRow");
  const setType = (temp) => {
    creatingTemp = temp;
    pop.querySelectorAll("#typeSeg button").forEach((b) => b.classList.toggle("active", b.dataset.temp === "1" === temp));
    lifeRow.hidden = !temp;
  };
  pop.querySelectorAll("#typeSeg button").forEach((b) => b.addEventListener("click", () => {
    if (!b.disabled) setType(b.dataset.temp === "1");
  }));
  if (mfull) setType(true);
  pop.querySelectorAll("#lifePresets button").forEach((b) => b.addEventListener("click", () => {
    if (b.dataset.burn) {
      burnOnRead = true;
      life = 0;
    } else {
      burnOnRead = false;
      life = Number(b.dataset.min);
    }
    pop.querySelectorAll("#lifePresets button").forEach((x) => x.classList.toggle("active", x === b));
  }));
  pop.querySelector("#diceBtn").addEventListener("click", () => {
    local.value = suggestName();
    local.focus();
  });
  const create = async () => {
    const errEl = pop.querySelector("#addrErr");
    errEl.textContent = "";
    const body = { localPart: local.value.trim(), isTemp: creatingTemp, groupId: pop.querySelector("#newGroupSel").value || null };
    if (creatingTemp) {
      if (burnOnRead) body.burnOnRead = true;
      else body.ttlMinutes = life;
    }
    const { ok, data } = await api("/api/mail/addresses", { body });
    if (!ok) {
      errEl.textContent = data.error || "That did not work.";
      return;
    }
    toast("Address created");
    pop.remove();
    await refresh();
  };
  pop.querySelector("#addrConfirm").addEventListener("click", create);
  local.addEventListener("keydown", (e) => {
    if (e.key === "Enter") create();
  });
  local.focus();
  setTimeout(() => {
    const onOutside = (e) => {
      if (!pop.contains(e.target) && e.target !== anchorEl) {
        pop.remove();
        document.removeEventListener("mousedown", onOutside, true);
      }
    };
    document.addEventListener("mousedown", onOutside, true);
  }, 0);
}
function runOnboarding() {
  return new Promise((resolve) => {
    const scrim = el("div", { class: "onboard" });
    document.body.appendChild(scrim);
    function stepAddress() {
      scrim.innerHTML = `<div class="onboard__card">
        <div class="onboard__step">You're all set</div>
        <h2>Your inbox is ready</h2>
        <p class="onboard__sub">It is end-to-end encrypted, so only you can read it. Mail sent here lands in your inbox:</p>
        <div class="codeblock onboard__code"><span>${esc(me.username)}@${esc(domain)}</span></div>
        <p class="onboard__sub">Want a throwaway alias too? It reaches the same inbox and burns itself after a day. Good for signups you don't fully trust.</p>
        <div class="onboard__alias">
          <div class="input-affix input-affix--suffix">
            <input class="input mono" id="obAlias" placeholder="alias name" spellcheck="false" autocomplete="off">
            <span class="affix">@${esc(domain)}</span>
          </div>
        </div>
        <div class="onboard__actions"><span class="onboard__err" id="obErr"></span><button class="btn btn--primary" id="obDone">Enter my inbox</button></div>
      </div>`;
      scrim.querySelector("#obDone").addEventListener("click", finish);
    }
    async function finish() {
      const btn = scrim.querySelector("#obDone");
      const alias = (scrim.querySelector("#obAlias")?.value || "").trim();
      setLoading(btn, true);
      if (alias) {
        const { ok, data } = await api("/api/mail/addresses", { body: { localPart: alias, isTemp: true, ttlMinutes: 1440 } });
        if (!ok) {
          setLoading(btn, false);
          scrim.querySelector("#obErr").textContent = data.error || "That alias is taken or invalid.";
          return;
        }
      }
      if (encMode !== "auto") await ensureUnlocked(myEncPrivateKey);
      await api("/api/onboarded", { body: {} });
      paintIdentity();
      scrim.remove();
      resolve();
    }
    stepAddress();
  });
}
function closeSidebar() {
  app.classList.remove("sidebar-open");
}
function wireEvents() {
  mountThemeToggles();
  $("#composeBtn").addEventListener("click", () => openCompose());
  $("#sideCompose").addEventListener("click", () => openCompose());
  $("#refreshBtn").addEventListener("click", () => {
    toast("Refreshed", { icon: "refresh", timeout: 1400 });
    refresh();
  });
  $("#mSearch")?.addEventListener("input", (e) => {
    query = e.target.value.trim();
    cursor = -1;
    renderList();
  });
  $("#newAddrBtn").addEventListener("click", (e) => openAddressPopover(e.currentTarget));
  $("#newGroupBtn").addEventListener("click", () => createGroup());
  $("#newFolderBtn").addEventListener("click", () => createFolder());
  $("#allMailItem").addEventListener("click", () => {
    filterId = null;
    filterGroup = null;
    filterFolder = null;
    cursor = -1;
    closeSidebar();
    render();
  });
  $("#junkItem").addEventListener("click", () => {
    filterFolder = "junk";
    filterId = null;
    filterGroup = null;
    cursor = -1;
    closeSidebar();
    render();
  });
  $$dir().forEach((b) => b.addEventListener("click", () => {
    direction = b.dataset.dir;
    cursor = -1;
    $$dir().forEach((x) => x.classList.toggle("active", x === b));
    if (openMsgId) closeReader();
    else renderList();
  }));
  const menu = $("#avatarMenu"), avBtn = $("#avatarBtn");
  avBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const open = menu.hidden;
    menu.hidden = !open;
    avBtn.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("click", (e) => {
    if (!menu.hidden && !menu.contains(e.target) && e.target !== avBtn) {
      menu.hidden = true;
      avBtn.setAttribute("aria-expanded", "false");
    }
  });
  $("#logoutBtn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" });
    clearSession();
    location.href = "/";
  });
  $("#navBurger").addEventListener("click", () => app.classList.toggle("sidebar-open"));
  $("#sidebarScrim").addEventListener("click", closeSidebar);
  $("#readerScrim").addEventListener("click", closeReader);
  document.addEventListener("keydown", onKey);
  reader.innerHTML = readerEmpty();
}
const $$dir = () => [...document.querySelectorAll(".dir-tab")];
function onKey(e) {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
  if (e.key === "Escape") {
    if (app.classList.contains("reader-open")) closeReader();
    else if (app.classList.contains("sidebar-open")) closeSidebar();
    else if (typing) document.activeElement.blur();
    return;
  }
  if (typing || e.metaKey || e.ctrlKey) return;
  const rows = visible();
  if (e.key === "j" || e.key === "ArrowDown") {
    e.preventDefault();
    cursor = Math.min(cursor + 1, rows.length - 1);
    renderList();
    scrollCursor();
  } else if (e.key === "k" || e.key === "ArrowUp") {
    e.preventDefault();
    cursor = Math.max(cursor - 1, 0);
    renderList();
    scrollCursor();
  } else if (e.key === "Enter" && cursor >= 0 && rows[cursor]) openMessage(rows[cursor]);
  else if (e.key === "u" && cursor >= 0 && rows[cursor] && direction === "in") setRead(rows[cursor], !rows[cursor].is_read);
  else if (e.key === "!" && cursor >= 0 && rows[cursor] && direction === "in") setJunk(rows[cursor], !rows[cursor].is_junk);
  else if ((e.key === "#" || e.key === "Delete") && cursor >= 0 && rows[cursor]) deleteMessage(rows[cursor]);
  else if (e.key === "c") {
    e.preventDefault();
    openCompose();
  } else if (e.key === "a") {
    e.preventDefault();
    openAddressPopover($("#newAddrBtn"));
  } else if (e.key === "r") {
    e.preventDefault();
    refresh();
  }
}
function scrollCursor() {
  document.querySelector(".mrow.cursor")?.scrollIntoView({ block: "nearest" });
}
boot();
