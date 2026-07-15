import { $, mountThemeToggles, mountPasswordReveals, promptModal, setLoading, icon } from "../shared/ui.js";
import { api } from "../shared/api.js";
mountThemeToggles();
mountPasswordReveals();
const form = $("#loginForm");
const statusEl = $("#formStatus");
const btn = $("#loginBtn");
function showStatus(msg) {
  statusEl.innerHTML = `${icon("alert", { size: 16 })}<span>${msg}</span>`;
  statusEl.classList.add("show");
}
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  statusEl.classList.remove("show");
  const username = form.username.value.trim();
  const password = form.password.value;
  if (!username || !password) {
    showStatus("Enter your username and password.");
    return;
  }
  setLoading(btn, true);
  const creds = { username, password: await ElusiveCrypto.deriveAuth(username, password) };
  let { ok, data } = await api("/api/login", { body: creds });
  if (!ok && data.totpRequired) {
    setLoading(btn, false);
    const code = await promptModal({
      title: "Two-factor code",
      body: "Enter the 6-digit code from your authenticator app, or one of your backup codes.",
      label: "Code",
      placeholder: "000000",
      mono: true,
      confirmText: "Verify",
      validate: (v) => /^\d{6}$/.test(v.trim()) || /^([a-f0-9]{10}|[a-f0-9]{20})$/i.test(v.trim().replace(/[\s-]/g, "")) ? "" : "Enter your 6-digit code or a backup code."
    });
    if (!code) return;
    setLoading(btn, true);
    ({ ok, data } = await api("/api/login", { body: { ...creds, totpCode: code.trim() } }));
  }
  if (!ok) {
    setLoading(btn, false);
    showStatus(data.error || "Something went wrong.");
    return;
  }
  window.location.href = "dashboard";
});
