import {
  $,
  $$,
  element as el,
  esc,
  icon,
  toast,
  confirmModal,
  promptModal,
  openModal,
  mountThemeToggles,
  setLoading,
  currentTheme,
  recoveryQRBlock
} from "../shared/ui.js";
import { api, setCsrf } from "../shared/api.js";
import { ensureUnlocked, decryptAll, verifyFingerprint, ensurePrekeys, resolveKey, clearSession, getArmoredKey, pageShield } from "../shared/crypto-session.js";
let me = null, domain = "", encMode = "auto", myEncPrivateKey = null, myPublicKey = null, totpEnabled = false;
const initials = (s) => (s || "?").trim().slice(0, 2).toUpperCase();
function download(name, text, type = "application/pgp-keys") {
  const a = el("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}
async function boot() {
  pageShield();
  mountThemeToggles();
  const { ok, data } = await api("/api/me");
  if (!ok) {
    location.href = "login";
    return;
  }
  me = data.user;
  domain = data.domain;
  encMode = data.encMode || "auto";
  myEncPrivateKey = data.encPrivateKey;
  myPublicKey = data.publicKey;
  totpEnabled = !!data.totpEnabled;
  setCsrf(data.csrf);
  if (encMode !== "auto") {
    await verifyFingerprint(myPublicKey, me.username);
    await ensureUnlocked(myEncPrivateKey);
    ensurePrekeys(myPublicKey);
  }
  paintProfile();
  render2fa();
  renderEncryption();
  initTheme();
  wire();
  scrollSpy();
  if (location.hash === "#encryption") $("#encryption")?.scrollIntoView();
}
function paintProfile() {
  const ini = initials(me.nickname || me.username);
  $("#setAvatar").textContent = ini;
  $("#nickname").value = me.nickname || "";
  $("#setUsername").textContent = me.username;
  $("#setEmail").textContent = `${me.username}@${domain}`;
  $("#copyEmail").innerHTML = icon("copy", { size: 17 });
}
function wire() {
  $("#saveNick").addEventListener("click", async () => {
    const btn = $("#saveNick");
    setLoading(btn, true);
    const { ok, data } = await api("/api/profile", { body: { nickname: $("#nickname").value.trim() } });
    setLoading(btn, false);
    if (!ok) {
      toast(data.error || "Could not save.", { icon: "alert" });
      return;
    }
    me.nickname = data.nickname;
    $("#setAvatar").textContent = initials(me.nickname || me.username);
    toast("Profile saved");
  });
  $("#copyEmail").addEventListener("click", async () => {
    await navigator.clipboard.writeText(`${me.username}@${domain}`);
    toast("Address copied");
  });
  $("#logoutBtn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" });
    clearSession();
    location.href = "/";
  });
  $("#logoutAllBtn").addEventListener("click", async () => {
    const { ok, data } = await api("/api/logout-all", { body: {} });
    toast(ok ? "Signed out on all other devices" : data.error || "Could not do that", { icon: ok ? "shieldCheck" : "alert" });
  });
  $("#regenRecoveryBtn").addEventListener("click", async () => {
    if (encMode !== "private") {
      toast("Recovery codes apply to end-to-end accounts with the key stored here.", { icon: "alert" });
      return;
    }
    await ensureUnlocked(myEncPrivateKey);
    const stash = getArmoredKey();
    if (!stash) return;
    const mat = await ElusiveCrypto.newRecovery(stash);
    const { ok, data } = await api("/api/recovery/regenerate", { body: { encPrivateKeyRecovery: mat.encPrivateKeyRecovery, recoveryHash: mat.recoveryHash } });
    if (!ok) {
      toast(data.error || "Could not regenerate.", { icon: "alert" });
      return;
    }
    await showRecoveryCode(mat.recoveryCode);
  });
  $$("#themeSeg button").forEach((b) => b.addEventListener("click", () => setTheme(b.dataset.themeChoice)));
  $("#exportDataBtn").addEventListener("click", async () => {
    const btn = $("#exportDataBtn");
    setLoading(btn, true);
    const { ok, data } = await api("/api/account/export");
    setLoading(btn, false);
    if (!ok) {
      toast(data.error || "Could not export.", { icon: "alert" });
      return;
    }
    download(`elusive-export-${me.username}.json`, JSON.stringify(data, null, 2), "application/json");
    toast("Export downloaded");
  });
  $("#deleteAccountBtn").addEventListener("click", async () => {
    const yes = await confirmModal({
      title: "Delete your account?",
      body: "This deletes your account, every address, and all stored mail. There is no undo.",
      confirmText: "Continue",
      danger: true
    });
    if (!yes) return;
    const pass = await promptModal({
      title: "Confirm your password",
      body: "Enter your password to permanently delete your account.",
      label: "Password",
      type: "password",
      confirmText: "Delete my account",
      validate: (v) => v ? "" : "Enter your password."
    });
    if (!pass) return;
    const proof = await ElusiveCrypto.deriveAuth(me.username, pass);
    const { ok, data } = await api("/api/account/delete", { body: { password: proof } });
    if (!ok) {
      toast(data.error || "Incorrect password.", { icon: "alert" });
      return;
    }
clearSession();
    location.href = "/";
  });
}

function render2fa() {
  const control = $("#twofaControl");
  const enroll = $("#twofaEnroll");
  enroll.innerHTML = "";
  control.innerHTML = "";
  $("#twofaDesc").textContent = totpEnabled ? "Two-factor is on. A code from your authenticator app is required at login." : "A time-based code from your authenticator app, required at login.";
  if (totpEnabled) {
    const badge = el("span", { class: "badge badge--dot", text: "On" });
    const btn = el("button", { class: "btn btn--danger", text: "Disable" });
    btn.addEventListener("click", disable2fa);
    control.append(badge, btn);
  } else {
    const btn = el("button", { class: "btn btn--secondary", text: "Enable" });
    btn.addEventListener("click", enable2fa);
    control.append(btn);
  }
}
async function enable2fa() {
  const { ok, data } = await api("/api/2fa/setup", { body: {} });
  if (!ok) {
    toast(data.error || "Could not start setup.", { icon: "alert" });
    return;
  }
  const enroll = $("#twofaEnroll");
  enroll.innerHTML = `
    <div class="twofa-enroll">
      <div class="set-row__desc">Add this secret to your authenticator app, then enter the 6-digit code it shows.</div>
      <div class="codeblock"><span>${esc(data.secret)}</span>
        <button class="btn btn--icon btn--ghost" id="twofaCopy" data-tooltip="Copy">${icon("copy", { size: 17 })}</button></div>
      <div class="twofa-enroll__row">
        <input class="input" id="twofaCode" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="off">
        <button class="btn btn--primary" id="twofaConfirm">Confirm</button>
      </div>
      <div class="twofa-err" id="twofaErr"></div>
    </div>`;
  $("#twofaCopy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(data.secret);
    toast("Secret copied");
  });
  const confirm = async () => {
    const code = $("#twofaCode").value.trim();
    if (!/^\d{6}$/.test(code)) {
      $("#twofaErr").textContent = "Enter the 6 digits from your app.";
      return;
    }
    const btn = $("#twofaConfirm");
    setLoading(btn, true);
    const r = await api("/api/2fa/enable", { body: { code } });
    setLoading(btn, false);
    if (!r.ok) {
      $("#twofaErr").textContent = r.data.error || "That code did not match.";
      return;
    }
    totpEnabled = true;
    showBackupCodes(r.data.backupCodes || []);
    toast("Two-factor enabled", { icon: "shieldCheck" });
  };
  $("#twofaConfirm").addEventListener("click", confirm);
  $("#twofaCode").addEventListener("keydown", (e) => {
    if (e.key === "Enter") confirm();
  });
  $("#twofaCode").focus();
}
function showBackupCodes(codes) {
  const enroll = $("#twofaEnroll");
  enroll.innerHTML = `
    <div class="twofa-enroll">
      <div class="set-row__desc"><strong>Save your backup codes.</strong> Each works once if you lose your authenticator. We cannot show them again.</div>
      <div class="codeblock" style="flex-wrap:wrap;gap:8px 18px;justify-content:flex-start">${codes.map((c) => `<span class="mono">${esc(c)}</span>`).join("")}</div>
      <div class="twofa-enroll__row">
        <button class="btn btn--secondary" id="bcCopy">${icon("copy", { size: 16 })} Copy all</button>
        <button class="btn btn--primary" id="bcDone">I saved them</button>
      </div>
    </div>`;
  $("#bcCopy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(codes.join("\n"));
    toast("Backup codes copied");
  });
  $("#bcDone").addEventListener("click", () => render2fa());
}
async function disable2fa() {
  const code = await promptModal({
    title: "Disable two-factor",
    body: "Enter a current code from your authenticator app, or one of your backup codes.",
    label: "Authenticator or backup code",
    placeholder: "000000",
    mono: true,
    confirmText: "Disable",
    validate: (v) => /^\d{6}$/.test(v.trim()) || /^([a-f0-9]{10}|[a-f0-9]{20})$/i.test(v.trim().replace(/[\s-]/g, "")) ? "" : "Enter your 6-digit code or a backup code."
  });
  if (!code) return;
  const { ok, data } = await api("/api/2fa/disable", { body: { code: code.trim() } });
  if (!ok) {
    toast(data.error || "That code did not match.", { icon: "alert" });
    return;
  }
  totpEnabled = false;
  render2fa();
  toast("Two-factor disabled");
}
const encMeta = {
  auto: { icon: "lock", title: "Server-managed", desc: "Your mail is encrypted at rest, but we hold the key and can read it. Convenient, and recovery is simple." },
  private: { icon: "key", title: "End-to-end, key stored with us", desc: "Only you can read your mail. We keep a passphrase-locked copy of your key, so a recovery code can get you back in." },
  keyfile: { icon: "key", title: "End-to-end, you hold the keyfile", desc: "Only you can read your mail, and we store no copy of your key. Lose the file and its passphrase and your mail is gone." }
};
async function renderEncryption() {
  const m = encMeta[encMode];
  const cur = $("#encCurrent");
  cur.innerHTML = `
    <div class="enc-current">
      <div class="enc-current__icon">${icon(m.icon, { size: 20 })}</div>
      <div>
        <div class="enc-current__title">${m.title} <span class="badge badge--dot">current</span></div>
        <div class="enc-current__desc">${m.desc}</div>
        <div class="enc-fp" id="encFp"></div>
      </div>
    </div>`;
  if (encMode !== "auto" && myPublicKey) {
    try {
      $("#encFp").textContent = `key fingerprint \xB7 ${await ElusiveCrypto.fingerprint(myPublicKey)}`;
    } catch {
    }
  }
  const actions = $("#encActions");
  actions.innerHTML = "";
  const add = (label, act, danger) => {
    const b = el("button", { class: "btn " + (danger ? "btn--danger" : "btn--secondary"), text: label });
    b.addEventListener("click", () => encAction(act));
    actions.appendChild(b);
  };
  if (encMode === "auto") {
    add("Turn on end-to-end, keep my key with Elusive", "enable-private");
    add("Turn on end-to-end, I hold the keyfile", "enable-keyfile");
  } else if (encMode === "private") {
    add("Switch to keyfile, I take the only copy", "to-keyfile");
    add("Turn off end-to-end", "disable", true);
  } else {
    add("Store my key with Elusive again", "to-server");
    add("Turn off end-to-end", "disable", true);
  }
}
const status = (msg) => {
  $("#encStatus").textContent = msg || "";
};
function showRecoveryCode(code) {
  return openModal((finish) => {
    const modal = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Recovery code" });
    modal.innerHTML = `
      <h2 class="modal__title">Your recovery code</h2>
      <p class="modal__body">Write this down and keep it somewhere safe. We cannot show it again, and we cannot recover it for you.</p>
      <div class="codeblock" style="margin-top:12px"><span>${esc(code)}</span>
        <button class="btn btn--icon btn--ghost" id="rcCopy" data-tooltip="Copy">${icon("copy", { size: 17 })}</button></div>
      <div id="rcQR"></div>
      <div class="modal__actions"><button class="btn btn--primary" id="rcDone" autofocus>I saved it</button></div>`;
    recoveryQRBlock(code).then((n) => modal.querySelector("#rcQR").replaceWith(n)).catch(() => {
    });
    modal.querySelector("#rcCopy").addEventListener("click", async () => {
      await navigator.clipboard.writeText(code);
      toast("Recovery code copied");
    });
    modal.querySelector("#rcDone").addEventListener("click", () => finish(true));
    return modal;
  }, { dismissable: false });
}
function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s);
}
async function loadAllPlaintext() {
  const { data } = await api("/api/mail/addresses");
  const addrs = data.addresses || [];
  const inboxes = await Promise.all(addrs.map((a) => api(`/api/mail/inbox/${a.id}`).then((r) => r.data.messages || [])));
  const all = inboxes.flat();
  await decryptAll(all);
  if (all.some((m) => m.locked)) throw new Error("locked");
  const attachments = [];
  for (const m of all) {
    for (const at of m.attachments || []) {
      if (!at.enc_key) continue;
      const res = await fetch(`/api/mail/attachment/${at.id}`);
      if (!res.ok) throw new Error("locked");
      const env = await res.json();
      const key = await resolveKey(env.encKey);
      const cipher = Uint8Array.from(atob(env.data), (c) => c.charCodeAt(0));
      const plain = await ElusiveCrypto.decryptAttachment(key, cipher);
      attachments.push({ id: at.id, data: bytesToB64(plain) });
    }
  }
  return {
    messages: all.map((m) => ({ id: m.id, subject: m.subject, body: m.body, from: m.from_addr, to: m.to_addr })),
    attachments,
  };
}
async function encAction(act) {
  status("");
  try {
    if (act === "enable-private" || act === "enable-keyfile") {
      const custody = act === "enable-keyfile" ? "keyfile" : "private";
      const pass = await promptModal({
        title: "Protect your key",
        body: "Choose a passphrase for your key. You will need it every session.",
        label: "Passphrase",
        type: "password",
        placeholder: "At least 10 characters",
        confirmText: "Turn on end-to-end",
        validate: (v) => v.length >= 10 ? "" : "Use at least 10 characters."
      });
      if (!pass) return;
      status("Re-encrypting your mailbox. This can take a moment.");
      const id = await ElusiveCrypto.createIdentity(me.username, pass);
      const body = { custody, publicKey: id.publicKey };
      if (custody === "private") Object.assign(body, { encPrivateKey: id.encPrivateKey, encPrivateKeyRecovery: id.encPrivateKeyRecovery, recoveryHash: id.recoveryHash });
      const { ok, data } = await api("/api/enc/enable-e2e", { body });
      if (!ok) {
        status(data.error || "That did not work.");
        return;
      }
      await ensurePrekeys(id.publicKey);
      localStorage.setItem(`elusive_fp_${me.username}`, await ElusiveCrypto.fingerprint(id.publicKey));
      if (custody === "keyfile") {
        download("elusive-key.asc", id.encPrivateKey);
        await confirmModal({ title: "Keyfile downloaded", body: "Keep it safe. Without it and your passphrase, your mail cannot be recovered.", confirmText: "Got it", cancelText: "Close" });
      } else {
        await showRecoveryCode(id.recoveryCode);
      }
      location.reload();
      return;
    }
    if (act === "disable") {
      const yes = await confirmModal({ title: "Turn off end-to-end?", body: "Elusive will be able to read your mail again. Your mailbox is re-encrypted with our key.", confirmText: "Turn it off", danger: true });
      if (!yes) return;
      status("Re-encrypting your mailbox.");
      let plaintext;
      try {
        plaintext = await loadAllPlaintext();
      } catch {
        status("Some mail could not be decrypted, so this is not safe to convert.");
        return;
      }
      const { ok, data } = await api("/api/enc/disable-e2e", { body: plaintext });
      if (!ok) {
        status(data.error || "That did not work.");
        return;
      }
      clearSession();
      location.reload();
      return;
    }
    if (act === "to-keyfile") {
      const yes = await confirmModal({ title: "Take the only copy?", body: "Elusive hands you the only copy of your key and forgets it. Lose it and your mail is gone, with no recovery.", confirmText: "Download and take over", danger: true });
      if (!yes) return;
      download("elusive-key.asc", myEncPrivateKey);
      const { ok, data } = await api("/api/enc/to-keyfile", { body: {} });
      if (!ok) {
        status(data.error || "That did not work.");
        return;
      }
      await confirmModal({ title: "Keyfile downloaded", body: "Elusive no longer holds your key. Its passphrase is your current login password.", confirmText: "Got it", cancelText: "Close" });
      location.reload();
      return;
    }
    if (act === "to-server") {
      const pass = await promptModal({
        title: "Store your key with Elusive",
        body: "Choose a passphrase to lock the key Elusive will store.",
        label: "Passphrase",
        type: "password",
        placeholder: "At least 10 characters",
        confirmText: "Store it",
        validate: (v) => v.length >= 10 ? "" : "Use at least 10 characters."
      });
      if (!pass) return;
      const mat = await ElusiveCrypto.serverCustodyMaterial(getArmoredKey(), pass);
      const { ok, data } = await api("/api/enc/to-server", { body: { encPrivateKey: mat.encPrivateKey, encPrivateKeyRecovery: mat.encPrivateKeyRecovery, recoveryHash: mat.recoveryHash } });
      if (!ok) {
        status(data.error || "That did not work.");
        return;
      }
      await showRecoveryCode(mat.recoveryCode);
      location.reload();
      return;
    }
  } catch (e) {
    status("Something went wrong. Try again.");
  }
}
function initTheme() {
  const saved = localStorage.getItem("elusive_theme");
  markTheme(saved || "system");
}
function markTheme(choice) {
  $$("#themeSeg button").forEach((b) => b.classList.toggle("active", b.dataset.themeChoice === choice));
}
function setTheme(choice) {
  if (choice === "system") {
    document.documentElement.removeAttribute("data-theme");
    localStorage.removeItem("elusive_theme");
  } else {
    document.documentElement.setAttribute("data-theme", choice);
    localStorage.setItem("elusive_theme", choice);
  }
  markTheme(choice);
}
function scrollSpy() {
  const links = $$("#settingsNav a");
  const byId = Object.fromEntries(links.map((a) => [a.getAttribute("href").slice(1), a]));
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        links.forEach((l) => l.classList.remove("active"));
        byId[e.target.id]?.classList.add("active");
      }
    });
  }, { rootMargin: "-40% 0px -55% 0px" });
  $$(".set-section").forEach((s) => obs.observe(s));
}
boot();
