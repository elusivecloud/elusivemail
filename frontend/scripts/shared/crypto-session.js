import { openModal, element as el, icon } from "./ui.js";
import { api } from "./api.js";
import { getCachedMessage, putCachedMessage, clearCache } from "./mail-cache.js";
let privKey = null;
let armoredKey = null;
export function getPrivKey() {
  return privKey;
}
export function getArmoredKey() {
  return armoredKey;
}
export function clearSession() {
  privKey = null;
  armoredKey = null;
  prekeyCache.clear();
  clearCache();
}

const prekeyCache = new Map(); // one-shot per tag, server burns the onetime key after
export function resolveKey(tag) {
  if (!tag || tag === "pgp") return Promise.resolve(privKey);
  if (prekeyCache.has(tag)) return prekeyCache.get(tag);
  const p = (async () => {
    const [, kind, id] = tag.split(":");
    const { ok, data } = await api(`/api/enc/prekeys/${id}`);
    if (!ok) throw new Error("prekey unavailable");
    const key = await ElusiveCrypto.unwrapPrekey(privKey, data.encPrivateKey);
    if (kind === "onetime") api(`/api/enc/prekeys/${id}`, { method: "DELETE" }).catch(() => {});
    return key;
  })();
  prekeyCache.set(tag, p);
  return p;
}

export async function ensurePrekeys(publicKey) {
  if (!publicKey) return;
  const { ok, data } = await api("/api/enc/prekeys/status");
  if (!ok) return;
  const publish = {};
  if (data.needsSigned) {
    publish.signed = (await ElusiveCrypto.generatePrekeys(publicKey, 1))[0];
  }
  if (data.onetimeCount < data.lowWatermark) {
    publish.onetime = await ElusiveCrypto.generatePrekeys(publicKey, data.topUp);
  }
  if (publish.signed || publish.onetime) await api("/api/enc/prekeys", { body: publish });
}
export async function ensureUnlocked(encPrivateKey) {
  if (privKey) return privKey;
  const keyfile = !encPrivateKey;
  await openModal((finish) => {
    const modal = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Unlock your mail" });
    modal.innerHTML = `
      <h2 class="modal__title">Unlock your mail</h2>
      <p class="modal__body">${keyfile ? "Paste your key file and its passphrase. Decryption happens here, in your browser." : "Enter your password to decrypt this session. It never leaves your browser."}</p>
      <form class="unlock-body">
        ${keyfile ? `<div class="field"><label class="field-label" for="ukFile">Key file</label>
          <textarea class="textarea mono" id="ukFile" rows="4" placeholder="Paste your .asc key here" autofocus></textarea></div>` : ""}
        <div class="field">
          <label class="field-label" for="ukPw">${keyfile ? "Key passphrase" : "Password"}</label>
          <div class="input-affix">
            <input class="input" id="ukPw" type="password" autocomplete="current-password" ${keyfile ? "" : "autofocus"}>
            <button type="button" class="btn btn--icon btn--ghost input-reveal" data-reveal></button>
          </div>
          <div class="field-error" id="ukErr"><span>${icon("alert", { size: 14 })}</span><span class="t"></span></div>
        </div>
        <button class="btn btn--primary btn--block" type="submit">Unlock</button>
      </form>`;
    const reveal = modal.querySelector("[data-reveal]");
    const pw = modal.querySelector("#ukPw");
    reveal.innerHTML = icon("eye", { size: 18 });
    reveal.addEventListener("click", () => {
      const show = pw.type === "password";
      pw.type = show ? "text" : "password";
      reveal.innerHTML = icon(show ? "eyeOff" : "eye", { size: 18 });
    });
    const errWrap = modal.querySelector("#ukErr");
    const errText = errWrap.querySelector(".t");
    const field = errWrap.closest(".field");
    modal.querySelector("form").addEventListener("submit", async (e) => {
      e.preventDefault();
      field.classList.remove("has-error");
      try {
        const locked = keyfile ? modal.querySelector("#ukFile").value.trim() : encPrivateKey;
        const unlocked = await ElusiveCrypto.unlockKey(locked, pw.value);
        armoredKey = unlocked;
        privKey = await ElusiveCrypto.loadKey(unlocked);
        finish(true);
      } catch {
        field.classList.add("has-error");
        errText.textContent = keyfile ? "That key or passphrase didn't work." : "Wrong password.";
      }
    });
    return modal;
  }, { dismissable: false });
  return privKey;
}
const armored = (v) => typeof v === "string" && v.startsWith("-----BEGIN PGP");

export async function decryptAll(list) {
  if (!privKey) return;
  await Promise.all(list.map(async (m) => {
    if (!m.enc_key) return;
    try {
      const cached = await getCachedMessage(m.id);
      if (cached) {
        Object.assign(m, cached);
      } else {
        const key = await resolveKey(m.enc_key);
        const { subject, body } = await ElusiveCrypto.decryptMessage(key, m.subject, m.body);
        let from_addr = m.from_addr, to_addr = m.to_addr;
        if (armored(m.from_addr)) {
          const env = await ElusiveCrypto.decryptMessage(key, m.from_addr, m.to_addr);
          from_addr = env.subject;
          to_addr = env.body;
        }
        m.subject = subject; m.body = body; m.from_addr = from_addr; m.to_addr = to_addr;
        await putCachedMessage(m.id, { subject, body, from_addr, to_addr });
      }
    } catch {
      m.subject = "[unable to decrypt]";
      m.body = "";
      if (armored(m.from_addr)) { m.from_addr = ""; m.to_addr = ""; }
      m.locked = true;
    }
    delete m.enc_key;
  }));
}
export async function verifyFingerprint(publicKey, username) {
  if (!publicKey) return null;
  const fp = await ElusiveCrypto.fingerprint(publicKey);
  const pinKey = `elusive_fp_${username}`;
  const pinned = localStorage.getItem(pinKey);
  if (!pinned) {
    localStorage.setItem(pinKey, fp);
    return fp;
  }
  if (pinned !== fp) {
    const banner = el("div", { class: "banner banner--fixed fp-banner", role: "alert" });
    banner.innerHTML = `<span class="banner__icon">${icon("alert", { size: 18 })}</span>
      <span>Your encryption key fingerprint changed since your last visit. Do not trust this session until you verify it out of band.</span>`;
    document.body.appendChild(banner);
  }
  return pinned;
}

export function pageShield() {
  document.addEventListener("pagehide", () => {
    privKey = null;
    armoredKey = null;
    prekeyCache.clear();
    clearCache();
  });
}
