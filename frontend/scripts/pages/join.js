import { $, esc, mountThemeToggles, mountPasswordReveals, setLoading, icon, recoveryQRBlock } from "../shared/ui.js";
import { api } from "../shared/api.js";
mountThemeToggles();
mountPasswordReveals();
const form = $("#joinForm");
const statusEl = $("#formStatus");
const btn = $("#joinBtn");
const pw = $("#password");
const meter = $("#pwMeter");
const pwHint = $("#pwHint");
const USERNAME_RE = /^[a-z0-9_.-]{3,20}$/i;
function showStatus(msg) {
  statusEl.innerHTML = `${icon("alert", { size: 16 })}<span>${msg}</span>`;
  statusEl.classList.add("show");
}
function scorePassword(v) {
  let s = 0;
  if (v.length >= 10) s++;
  if (v.length >= 14) s++;
  if (/[a-z]/.test(v) && /[A-Z0-9]/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  return Math.min(s, 4);
}
pw.addEventListener("input", () => {
  const v = pw.value;
  const s = v ? scorePassword(v) : 0;
  meter.dataset.score = s;
  pwHint.textContent = !v ? "Long and unique beats short and clever." : v.length < 10 ? `${10 - v.length} more character${10 - v.length === 1 ? "" : "s"} to go.` : ["", "Okay.", "Good.", "Strong.", "Excellent."][s];
});
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  statusEl.classList.remove("show");
  const username = form.username.value.trim();
  const password = form.password.value;
  if (!USERNAME_RE.test(username)) {
    showStatus("Username must be 3 to 20 characters: letters, numbers, . _ -");
    form.username.focus();
    return;
  }
  if (password.length < 10) {
    showStatus("Password must be at least 10 characters.");
    pw.focus();
    return;
  }
  if (!form.tos.checked) {
    showStatus("Please accept the terms to continue.");
    return;
  }
  setLoading(btn, true, "Generating your keys");
  let id, authProof;
  try {
    id = await ElusiveCrypto.createIdentity(username, password);
    authProof = await ElusiveCrypto.deriveAuth(username, password);
  } catch {
    setLoading(btn, false);
    showStatus("Could not set up encryption in this browser.");
    return;
  }
  const { ok, data } = await api("/api/join", {
    body: {
      username,
      password: authProof,
      tos: true,
      publicKey: id.publicKey,
      encPrivateKey: id.encPrivateKey,
      encPrivateKeyRecovery: id.encPrivateKeyRecovery,
      recoveryHash: id.recoveryHash
    }
  });
  if (!ok) {
    setLoading(btn, false);
    showStatus(data.error || "Something went wrong.");
    return;
  }
  localStorage.setItem(`elusive_fp_${username}`, await ElusiveCrypto.fingerprint(id.publicKey));
  showRecoveryCode(id.recoveryCode);
});
function showRecoveryCode(code) {
  const card = document.querySelector(".auth-card");
  card.innerHTML = `
    <div class="auth-card__head">
      <h1>Save your recovery code</h1>
      <p>This is the only way back in if you forget your password. We cannot show it again, and we cannot recover it for you.</p>
    </div>
    <div class="auth-form">
      <div class="codeblock"><span class="mono">${esc(code)}</span>
        <button class="btn btn--icon btn--ghost" id="rcCopy" type="button" data-tooltip="Copy">${icon("copy", { size: 17 })}</button></div>
      <div id="rcQR"></div>
      <label class="check">
        <input type="checkbox" id="rcAck">
        <span class="check__box" aria-hidden="true"></span>
        <span>I have saved this code somewhere safe</span>
      </label>
      <button class="btn btn--primary btn--lg btn--block" id="rcDone" type="button" disabled>Enter my inbox</button>
    </div>`;
  recoveryQRBlock(code).then((n) => card.querySelector("#rcQR").replaceWith(n)).catch(() => {
  });
  const done = card.querySelector("#rcDone");
  card.querySelector("#rcAck").addEventListener("change", (ev) => {
    done.disabled = !ev.target.checked;
  });
  card.querySelector("#rcCopy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code);
    } catch {
    }
  });
  done.addEventListener("click", () => {
    window.location.href = "dashboard";
  });
}
