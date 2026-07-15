import { icon, mountThemeToggles } from "../shared/ui.js";
localStorage.setItem("elusive_update_seen", "1");
mountThemeToggles();

const tools = document.querySelector("#mockTools");
if (tools) tools.innerHTML = ["mailOpen", "reply", "ban", "trash"].map((ic) => `<span class="mrow__tool">${icon(ic, { size: 15 })}</span>`).join("");

const item = (ic, label, danger) => `<span class="ctxmenu__item${danger ? " danger" : ""}"><span class="ctxmenu__glyph">${icon(ic, { size: 15 })}</span><span class="ctxmenu__label">${label}</span></span>`;
const menu = document.querySelector("#mockMenu");
if (menu) menu.innerHTML = [
  item("mail", "Open") + item("reply", "Reply") + item("forward", "Forward"),
  item("mailOpen", "Mark as unread") + item("copy", "Copy sender address") + item("ban", "Mark as junk"),
  item("folder", "Move to “Receipts”"),
  item("sliders", "Customize quick actions"),
  item("trash", "Delete", true)
].join('<div class="ctxmenu__sep"></div>');

const qr = document.querySelector("#mockQR");
if (qr) import("../vendor/qr.js").then(({ qrSVG }) => {
  qr.innerHTML = qrSVG("https://example.invalid/recover#rc=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", { module: 3, margin: 2 });
}).catch(() => {});
