export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(c));
  }
  return node;
}
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const ICONS = {
  inbox: '<path d="M4 13h4l1.5 2.5h5L16 13h4"/><path d="M5.5 5h13l2.5 8v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4l2.5-8Z"/>',
  send: '<path d="M21 4 3 11l6 2.5L11 20l3-6 7-10Z"/><path d="M9 13.5 21 4"/>',
  compose: '<path d="M12 20h8"/><path d="M16.5 4.5a1.8 1.8 0 0 1 2.6 2.6L8 18l-4 1 1-4 11.5-10.5Z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M3.5 6.5h17"/><path d="M8.5 6.5V5a1.5 1.5 0 0 1 1.5-1.5h4A1.5 1.5 0 0 1 15.5 5v1.5"/><path d="M6.5 6.5 7.4 19a1.5 1.5 0 0 0 1.5 1.4h6.2a1.5 1.5 0 0 0 1.5-1.4l.9-12.5"/>',
  copy: '<rect x="9" y="9" width="11.5" height="11.5" rx="2.4"/><path d="M5 15.5H4.5A2.5 2.5 0 0 1 2 13V4.5A2.5 2.5 0 0 1 4.5 2H13a2.5 2.5 0 0 1 2.5 2.5V5"/>',
  check: '<path d="M20 6.5 9.2 17.3 4 12.1"/>',
  checkCircle: '<path d="M21.5 11.1V12a9.5 9.5 0 1 1-5.6-8.7"/><path d="M21.5 4.5 12 14l-2.8-2.8"/>',
  alert: '<path d="M10.6 4 2.4 18a1.6 1.6 0 0 0 1.4 2.4h16.4a1.6 1.6 0 0 0 1.4-2.4L13.4 4a1.6 1.6 0 0 0-2.8 0Z"/><path d="M12 9.5v4.5"/><path d="M12 17.5h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.7h.01"/>',
  shield: '<path d="M12 21.5s7.5-3.8 7.5-9.5V5.2L12 2.5 4.5 5.2V12c0 5.7 7.5 9.5 7.5 9.5Z"/>',
  shieldCheck: '<path d="M12 21.5s7.5-3.8 7.5-9.5V5.2L12 2.5 4.5 5.2V12c0 5.7 7.5 9.5 7.5 9.5Z"/><path d="m8.8 11.8 2.2 2.2 4-4.4"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.3"/><path d="m10.6 12.5 8.4-8.4"/><path d="m15.5 7 2.5 2.5"/><path d="m17.8 4.7 2.5 2.5"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="10.5" rx="2.2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
  lockOpen: '<rect x="4.5" y="10.5" width="15" height="10.5" rx="2.2"/><path d="M8 10.5V7.3a4 4 0 0 1 7.8-1.3"/>',
  user: '<circle cx="12" cy="8.2" r="3.9"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>',
  sliders: '<path d="M5 21v-6M5 11V3M12 21v-8M12 9V3M19 21v-4M19 13V3"/><path d="M2.5 15h5M9.5 9h5M16.5 17h5"/>',
  logout: '<path d="M9.5 21H5.5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 16.5 4.5-4.5L16 7.5"/><path d="M20.5 12H9.5"/>',
  chevronDown: '<path d="m6 9.5 6 6 6-6"/>',
  chevronRight: '<path d="m9.5 6 6 6-6 6"/>',
  arrowRight: '<path d="M4.5 12h15"/><path d="m13 5.5 6.5 6.5-6.5 6.5"/>',
  arrowLeft: '<path d="M19.5 12h-15"/><path d="m11 5.5-6.5 6.5 6.5 6.5"/>',
  close: '<path d="M18 6 6 18M6 6l12 12"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.2-4.2"/>',
  dice: '<rect x="3.5" y="3.5" width="17" height="17" rx="3.5"/><circle cx="8.5" cy="8.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="15.5" cy="15.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6"/>',
  moon: '<path d="M21 13a8.3 8.3 0 0 1-11-11 8.3 8.3 0 1 0 11 11Z"/>',
  menu: '<path d="M3.5 7h17M3.5 12h17M3.5 17h17"/>',
  eye: '<path d="M2 12s3.6-6.8 10-6.8S22 12 22 12s-3.6 6.8-10 6.8S2 12 2 12Z"/><circle cx="12" cy="12" r="2.8"/>',
  eyeOff: '<path d="M10.2 5.3A9.7 9.7 0 0 1 12 5.2c6.4 0 10 6.8 10 6.8a17.6 17.6 0 0 1-2.7 3.5"/><path d="M6.5 6.6A16.9 16.9 0 0 0 2 12s3.6 6.8 10 6.8a9.6 9.6 0 0 0 4-.9"/><path d="m9.9 10.1a2.8 2.8 0 0 0 4 3.9"/><path d="m3 3 18 18"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5.2l3.4 2"/>',
  at: '<circle cx="12" cy="12" r="3.6"/><path d="M15.6 8.4V13a2.9 2.9 0 0 0 5.8 0v-1a9.4 9.4 0 1 0-3.8 7.6"/>',
  download: '<path d="M12 3.5v11.5"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M4.5 20.5h15"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 4.5V10h-5.5"/>',
  card: '<rect x="2.5" y="5" width="19" height="14" rx="2.4"/><path d="M2.5 9.5h19"/><path d="M6 15h3"/>',
  zap: '<path d="M13 2.5 3.5 14H11l-1 7.5L20 10h-7.5l.5-7.5Z"/>',
  fingerprint: '<path d="M12 11.5a1.5 1.5 0 0 0-1.5 1.5c0 2 .2 4-1.3 5.8"/><path d="M8.2 7.6a5.5 5.5 0 0 1 8.3 3.4c.2.9.2 2 .1 3"/><path d="M4.8 9.2a9 9 0 0 1 14.4 1.6"/><path d="M12 14.5c0 3-.6 4.8-1.8 6.2"/><path d="M15.5 13c.2 3.2-.3 5.4-1.6 7.4"/>',
  star: '<path d="m12 3.5 2.6 5.3 5.8.9-4.2 4.1 1 5.8L12 17l-5.2 2.6 1-5.8L3.6 9.7l5.8-.9L12 3.5Z"/>',
  flame: '<path d="M12 3s5.5 3.8 5.5 9.3A5.5 5.5 0 0 1 6.5 12c0-1.8 1-3 1-3s.3 1.8 1.7 1.8C11 10.8 9.8 6 12 3Z"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.7 2.4 4.2 5.7 4.2 9s-1.5 6.6-4.2 9c-2.7-2.4-4.2-5.7-4.2-9S9.3 5.4 12 3Z"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2.4"/><path d="m3.8 6.5 8.2 6 8.2-6"/>',
  dot: '<circle cx="12" cy="12" r="4" fill="currentColor" stroke="none"/>',
  spark: '<path d="M12 3v5M12 16v5M3 12h5M16 12h5" stroke-width="1.6"/><path d="m6 6 2.6 2.6M15.4 15.4 18 18M18 6l-2.6 2.6M8.6 15.4 6 18"/>',
  arrowUpRight: '<path d="M7 17 17 7"/><path d="M8 7h9v9"/>',
  reply: '<path d="M9 16.5 3.5 11 9 5.5"/><path d="M3.5 11H15a5.5 5.5 0 0 1 5.5 5.5V19"/>',
  forward: '<path d="M15 16.5 20.5 11 15 5.5"/><path d="M20.5 11H9a5.5 5.5 0 0 0-5.5 5.5V19"/>',
  mailOpen: '<path d="M3 9.2 12 3l9 6.2V18a2.4 2.4 0 0 1-2.4 2.4H5.4A2.4 2.4 0 0 1 3 18V9.2Z"/><path d="m3.6 9.9 8.4 5.9 8.4-5.9"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>',
  grip: '<circle cx="9" cy="6" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="6" r="1.3" fill="currentColor" stroke="none"/><circle cx="9" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="9" cy="18" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="18" r="1.3" fill="currentColor" stroke="none"/>',
  folder: '<path d="M3.5 6.5a1.5 1.5 0 0 1 1.5-1.5h4.4l2 2.2H19a1.5 1.5 0 0 1 1.5 1.5v8.8a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5Z"/>'
};
export function icon(name, { size = 20, stroke = 1.6, cls = "" } = {}) {
  const body = ICONS[name] || "";
  return `<svg class="icon${cls ? " " + cls : ""}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${stroke}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}
export function markSVG(cls = "brand__mark") {
  const id = "mk" + Math.floor(performance.now() * 1e3).toString(36);
  return `<svg class="${cls}" viewBox="0 0 64 64" role="img" aria-label="Elusive">
    <mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
      <circle cx="32" cy="32" r="27" fill="#fff"/>
      <circle cx="32" cy="32" r="23.4" fill="none" stroke="#000" stroke-width="1.5"/>
      <rect x="22" y="20" width="5" height="24" rx="1" fill="#000"/>
      <rect x="26.5" y="20" width="15" height="5" rx="1" fill="#000"/>
      <rect x="26.5" y="30.5" width="10.5" height="5" rx="1" fill="#000"/>
      <rect x="26.5" y="39" width="15" height="5" rx="1" fill="#000"/>
    </mask>
    <circle cx="32" cy="32" r="27" fill="currentColor" mask="url(#${id})"/>
  </svg>`;
}
const THEME_KEY = "elusive_theme";
export function currentTheme() {
  const set = document.documentElement.getAttribute("data-theme");
  if (set) return set;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
export function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
  }
  return next;
}
export function mountThemeToggles() {
  $$("[data-theme-toggle]").forEach((btn) => {
    if (!btn.dataset.wired) {
      btn.innerHTML = `<span class="icon-sun">${icon("sun")}</span><span class="icon-moon">${icon("moon")}</span>`;
      btn.setAttribute("aria-label", "Toggle color theme");
      btn.addEventListener("click", toggleTheme);
      btn.dataset.wired = "1";
    }
  });
}
export function mountPasswordReveals(root = document) {
  $$("[data-reveal]", root).forEach((btn) => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = "1";
    btn.type = "button";
    btn.innerHTML = icon("eye", { size: 18 });
    btn.setAttribute("aria-label", "Show password");
    const input = btn.parentElement.querySelector("input");
    btn.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.innerHTML = icon(show ? "eyeOff" : "eye", { size: 18 });
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
      input.focus();
    });
  });
}
export function setLoading(btn, on, label) {
  if (!btn) return;
  if (on) {
    btn.dataset.label = btn.textContent;
    btn.classList.add("is-loading");
    btn.disabled = true;
  } else {
    btn.classList.remove("is-loading");
    btn.disabled = false;
    if (label ?? btn.dataset.label) btn.textContent = label ?? btn.dataset.label;
  }
}
export async function recoveryQRBlock(code) {
  const { qrSVG, qrCanvas } = await import("../vendor/qr.js");
  const url = `${location.origin}/recover#rc=${encodeURIComponent(code)}`;
  const wrap = el("div", { class: "rc-qr" });
  wrap.innerHTML = `
    <div class="rc-qr__img">${qrSVG(url, { module: 3, margin: 2 })}</div>
    <div class="rc-qr__side">
      <p>Prefer paper? Scan this with a phone camera and it opens the recovery page with the code already filled in.</p>
      <button class="btn btn--secondary btn--sm" type="button">${icon("download", { size: 15 })} Download QR card</button>
    </div>`;
  wrap.querySelector("button").addEventListener("click", () => {
    const qr = qrCanvas(url, { module: 10, margin: 4 });
    const W = 560, H = 700;
    const c = el("canvas");
    c.width = W;
    c.height = H;
    const x = c.getContext("2d");
    x.fillStyle = "#fff";
    x.fillRect(0, 0, W, H);
    x.textAlign = "center";
    x.fillStyle = "#000";
    x.font = "600 24px system-ui, sans-serif";
    x.fillText("Elusive recovery code", W / 2, 56);
    x.fillStyle = "#555";
    x.font = "14px system-ui, sans-serif";
    x.fillText("Scan with a phone camera, or type the code below.", W / 2, 84);
    x.imageSmoothingEnabled = false;
    x.drawImage(qr, (W - 400) / 2, 110, 400, 400);
    x.fillStyle = "#000";
    x.font = "600 19px ui-monospace, SFMono-Regular, monospace";
    x.fillText(code, W / 2, 560);
    x.fillStyle = "#555";
    x.font = "13px system-ui, sans-serif";
    x.fillText(`${location.host}/recover`, W / 2, 600);
    x.fillText("Keep this somewhere safe. Anyone who has it can reset your account.", W / 2, 640);
    c.toBlob((blob) => {
      const a = el("a", { href: URL.createObjectURL(blob), download: "elusive-recovery.png" });
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 3e3);
    });
  });
  return wrap;
}
function toastRegion() {
  let r = $(".toast-region");
  if (!r) {
    r = el("div", { class: "toast-region", "aria-live": "polite" });
    document.body.appendChild(r);
  }
  return r;
}
export function toast(msg, { icon: ic = "check", timeout = 3400 } = {}) {
  const node = el("div", { class: "toast", role: "status" });
  node.innerHTML = `<span class="toast__icon">${icon(ic, { size: 18 })}</span><span class="toast__msg"></span>`;
  node.querySelector(".toast__msg").textContent = msg;
  toastRegion().appendChild(node);
  const close = () => {
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), 220);
  };
  const t = setTimeout(close, timeout);
  node.addEventListener("click", () => {
    clearTimeout(t);
    close();
  });
  return close;
}
export function undoToast(msg, { onExpire, onUndo, timeout = 5e3 } = {}) {
  let done = false;
  const node = el("div", { class: "toast toast--undo", role: "status" });
  node.innerHTML = `<span class="toast__msg"></span><button class="toast__undo" type="button">Undo</button>`;
  node.querySelector(".toast__msg").textContent = msg;
  toastRegion().appendChild(node);
  const close = () => {
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), 220);
  };
  const t = setTimeout(() => {
    if (done) return;
    done = true;
    close();
    onExpire?.();
  }, timeout);
  node.querySelector(".toast__undo").addEventListener("click", () => {
    if (done) return;
    done = true;
    clearTimeout(t);
    close();
    onUndo?.();
  });
}
function openModal(render, { onKey, dismissable = true } = {}) {
  return new Promise((resolve) => {
    const scrim = el("div", { class: "scrim" });
    const prevFocus = document.activeElement;
    let done = false;
    const finish = (val) => {
      if (done) return;
      done = true;
      scrim.style.animation = "none";
      scrim.remove();
      document.removeEventListener("keydown", keyHandler, true);
      if (prevFocus && prevFocus.focus) prevFocus.focus();
      resolve(val);
    };
    const modal = render(finish);
    scrim.appendChild(modal);
    if (dismissable) scrim.addEventListener("mousedown", (e) => {
      if (e.target === scrim) finish(null);
    });
    const keyHandler = (e) => {
      if (e.key === "Escape" && dismissable) {
        e.preventDefault();
        finish(null);
        return;
      }
      if (e.key === "Tab") trapFocus(e, modal);
      if (onKey) onKey(e, finish);
    };
    document.addEventListener("keydown", keyHandler, true);
    document.body.appendChild(scrim);
    const focusables = modal.querySelectorAll("button, input, textarea, [tabindex]");
    (modal.querySelector("[autofocus]") || focusables[focusables.length - 1] || modal).focus();
  });
}
function trapFocus(e, container) {
  const f = [...container.querySelectorAll("button, input, textarea, select, a[href], [tabindex]:not([tabindex='-1'])")].filter((x) => !x.disabled && x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}
export function confirmModal({ title, body = "", confirmText = "Confirm", cancelText = "Cancel", danger = false, icon: ic } = {}) {
  return openModal((finish) => {
    const modal = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title });
    modal.innerHTML = `
      ${ic ? `<div class="modal__glyph">${icon(ic, { size: 22 })}</div>` : ""}
      <h2 class="modal__title"></h2>
      <div class="modal__body"></div>
      <div class="modal__actions">
        <button class="btn btn--ghost" data-cancel></button>
        <button class="btn ${danger ? "btn--danger" : "btn--primary"}" data-ok autofocus></button>
      </div>`;
    modal.querySelector(".modal__title").textContent = title;
    modal.querySelector(".modal__body").textContent = body;
    const ok = modal.querySelector("[data-ok]");
    ok.textContent = confirmText;
    const cancel = modal.querySelector("[data-cancel]");
    cancel.textContent = cancelText;
    ok.addEventListener("click", () => finish(true));
    cancel.addEventListener("click", () => finish(false));
    return modal;
  });
}
export function promptModal({ title, body = "", label = "", value = "", placeholder = "", type = "text", confirmText = "Continue", mono = false, validate } = {}) {
  return openModal((finish) => {
    const modal = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title });
    modal.innerHTML = `
      <h2 class="modal__title"></h2>
      ${body ? `<div class="modal__body"></div>` : ""}
      <form class="modal__form">
        <div class="field">
          ${label ? `<label class="field-label" for="pm-input"></label>` : ""}
          <input class="input${mono ? " mono" : ""}" id="pm-input" type="${type}" ${placeholder ? `placeholder="${esc(placeholder)}"` : ""} autofocus>
          <div class="field-error" id="pm-err"><span>${icon("alert", { size: 14 })}</span><span class="pm-err-text"></span></div>
        </div>
        <div class="modal__actions">
          <button type="button" class="btn btn--ghost" data-cancel>Cancel</button>
          <button type="submit" class="btn btn--primary"></button>
        </div>
      </form>`;
    modal.querySelector(".modal__title").textContent = title;
    if (body) modal.querySelector(".modal__body").textContent = body;
    if (label) modal.querySelector(".field-label").textContent = label;
    const input = modal.querySelector("#pm-input");
    input.value = value;
    modal.querySelector("[type=submit]").textContent = confirmText;
    const errBox = modal.querySelector("#pm-err"), errText = modal.querySelector(".pm-err-text");
    const field = modal.querySelector(".field");
    modal.querySelector("[data-cancel]").addEventListener("click", () => finish(null));
    modal.querySelector(".modal__form").addEventListener("submit", (e) => {
      e.preventDefault();
      const v = input.value;
      if (validate) {
        const msg = validate(v);
        if (msg) {
          field.classList.add("has-error");
          errText.textContent = msg;
          input.focus();
          return;
        }
      }
      finish(v);
    });
    input.addEventListener("input", () => field.classList.remove("has-error"));
    return modal;
  });
}
export function contextMenu(x, y, sections) {
  document.querySelectorAll(".ctxmenu").forEach((m) => m.remove());
  const menu = el("div", { class: "ctxmenu", role: "menu" });
  sections.filter((s) => s && s.length).forEach((group, i) => {
    if (i > 0) menu.appendChild(el("div", { class: "ctxmenu__sep" }));
    for (const item of group) {
      const btn = el("button", { class: "ctxmenu__item" + (item.danger ? " danger" : ""), role: "menuitem" });
      if (item.checked !== void 0) {
        btn.setAttribute("role", "menuitemcheckbox");
        btn.setAttribute("aria-checked", String(!!item.checked));
        btn.innerHTML = `<span class="ctxmenu__glyph">${item.checked ? icon("check", { size: 14 }) : ""}</span>`;
      } else if (item.icon) {
        btn.innerHTML = `<span class="ctxmenu__glyph">${icon(item.icon, { size: 15 })}</span>`;
      }
      btn.appendChild(el("span", { class: "ctxmenu__label", text: item.label }));
      btn.addEventListener("click", () => {
        close();
        item.onClick();
      });
      menu.appendChild(btn);
    }
  });
  document.body.appendChild(menu);
  const vw = window.innerWidth, vh = window.innerHeight;
  const rect = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, vw - rect.width - 8) + "px";
  menu.style.top = Math.min(y, vh - rect.height - 8) + "px";
  const close = () => {
    menu.remove();
    document.removeEventListener("mousedown", onOutside, true);
    document.removeEventListener("keydown", onKey, true);
  };
  const onOutside = (e) => {
    if (!menu.contains(e.target)) close();
  };
  const onKey = (e) => {
    if (e.key === "Escape") close();
  };
  setTimeout(() => {
    document.addEventListener("mousedown", onOutside, true);
    document.addEventListener("keydown", onKey, true);
  }, 0);
  return close;
}
export { openModal, el as element };
