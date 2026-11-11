// Small DOM helpers. Everything is built with textContent/text nodes, never innerHTML,
// so API data cannot inject markup.
export function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid != null && kid !== false) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

export async function api(path, opts = {}) {
  const res = await fetch(`/api${path}`, { headers: { "Content-Type": "application/json" }, ...opts });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
  return body;
}

export const post = (path, payload) => api(path, { method: "POST", body: JSON.stringify(payload) });

const TONES = {
  pass: "good", ok: "good", clean: "good",
  warn: "warn", warning: "warn", unknown: "warn",
  fail: "bad", critical: "bad", listed: "bad",
  skip: "muted"
};

export function badge(status, text) {
  return el("span", { class: `mm-badge mm-${TONES[status] || "muted"}` }, text ?? status);
}

// Works with the existing .test-button markup: <button><span>Label</span><span class="button-arrow">→</span></button>
export function setBusy(btn, busy) {
  const label = btn.querySelector("span");
  if (label) {
    if (!btn.dataset.label) btn.dataset.label = label.textContent;
    label.textContent = busy ? "Working…" : btn.dataset.label;
  }
  btn.disabled = busy;
}

// state: "" (normal) | "waiting" | "error"
export function setResult(out, state, ...kids) {
  out.className = state ? `result ${state}` : "result";
  out.replaceChildren(...kids);
}
