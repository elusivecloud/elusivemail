let csrf = null;
export function setCsrf(token) {
  csrf = token || null;
}
export async function api(path, opts = {}) {
  const method = opts.method || (opts.body !== void 0 ? "POST" : "GET");
  const headers = {};
  if (opts.body !== void 0) headers["Content-Type"] = "application/json";
  if (csrf && /^(POST|PUT|PATCH|DELETE)$/.test(method)) headers["x-csrf-token"] = csrf;
  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: opts.body !== void 0 ? JSON.stringify(opts.body) : void 0
    });
  } catch {
    return { ok: false, status: 0, data: { error: "network unavailable" } };
  }
  let data = {};
  try {
    data = await res.json();
  } catch {
  }
  return { ok: res.ok, status: res.status, data };
}
