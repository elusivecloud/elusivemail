import { $, mountThemeToggles, mountPasswordReveals, setLoading, toast, icon } from "../shared/ui.js";
import { api } from "../shared/api.js";
mountThemeToggles();
mountPasswordReveals();
const form = $("#recoverForm");
const statusEl = $("#formStatus");
const btn = $("#recoverBtn");
const rc = location.hash.match(/[#&]rc=([^&]+)/);
if (rc) {
  form.recoveryCode.value = decodeURIComponent(rc[1]).toUpperCase();
  form.username.focus();
}
function showStatus(msg) {
  statusEl.innerHTML = `${icon("alert", { size: 16 })}<span>${msg}</span>`;
  statusEl.classList.add("show");
}
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  statusEl.classList.remove("show");
  const username = form.username.value.trim();
  const recoveryCode = form.recoveryCode.value.trim().toUpperCase();
  const newPassword = form.newPassword.value;
  if (!username || !recoveryCode || !newPassword) {
    showStatus("All fields are required.");
    return;
  }
  if (newPassword.length < 10) {
    showStatus("New password must be at least 10 characters.");
    return;
  }
  setLoading(btn, true);
  const ch = await api("/api/recover/challenge", { body: { username } });
  if (!ch.ok) {
    setLoading(btn, false);
    showStatus(ch.data.error || "No recovery available for this account.");
    return;
  }
  let newEncPrivateKey;
  try {
    newEncPrivateKey = await ElusiveCrypto.rewrapKey(ch.data.encPrivateKeyRecovery, recoveryCode, newPassword);
  } catch {
    setLoading(btn, false);
    showStatus("That recovery code didn't work. Check for typos.");
    return;
  }
  const proof = await ElusiveCrypto.sha256hex(recoveryCode);
  const newAuth = await ElusiveCrypto.deriveAuth(username, newPassword);
  const { ok, data } = await api("/api/recover", { body: { username, recoveryProof: proof, newPassword: newAuth, newEncPrivateKey } });
  if (!ok) {
    setLoading(btn, false);
    showStatus(data.error || "Reset failed.");
    return;
  }
  setLoading(btn, false, "Password reset");
  toast("Password reset. Log in with your new password.", { icon: "checkCircle" });
  setTimeout(() => {
    window.location.href = "login";
  }, 1400);
});
