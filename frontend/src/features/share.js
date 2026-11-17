import { el, api, post, setBusy, setResult } from "./ui.js";
import { createFlow, checkBackend } from "./flow.js";

// Never export or share private keys / secrets, even though the generator shows them on screen.
const PEM_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
const SECRET_KEY_RE = /(priv(ate)?[_-]?key|passw(or)?d|secret|token|api[_-]?key)/i;

export function sanitize(value, depth = 0) {
  if (depth > 12) return undefined;
  if (typeof value === "string") return value.replace(PEM_RE, "[private key removed]");
  if (Array.isArray(value)) return value.map((v) => sanitize(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEY_RE.test(k) ? "[removed]" : sanitize(v, depth + 1)]));
  }
  return value;
}

function download(name, mime, content) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function flatten(obj, prefix = "", out = []) {
  if (Array.isArray(obj)) obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
  else if (obj && typeof obj === "object") Object.entries(obj).forEach(([k, v]) => flatten(v, prefix ? `${prefix}.${k}` : k, out));
  else out.push([prefix, obj ?? ""]);
  return out;
}

function toCsv(data) {
  const cell = (v) => {
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // spreadsheet formula-injection guard
    return `"${s.replace(/"/g, '""')}"`;
  };
  return ["field,value", ...flatten(data).map(([k, v]) => `${cell(k)},${cell(v)}`)].join("\r\n");
}

// Share link / JSON / CSV / PDF buttons. printTarget = the .result element to print.
export function resultActions(type, data, printTarget) {
  data = sanitize(data);
  const status = el("span", { class: "mm-note", role: "status" });
  const base = `mailmetrix-${type}-${new Date().toISOString().slice(0, 10)}`;

  const shareBtn = el("button", {
    type: "button",
    onclick: async () => {
      shareBtn.disabled = true;
      status.textContent = "Creating link…";
      try {
        const { id, expiresAt } = await post("/share", { type, data });
        const url = `${location.origin}/?share=${id}`;
        let copied = false;
        try { await navigator.clipboard.writeText(url); copied = true; } catch { /* clipboard blocked */ }
        status.replaceChildren(
          copied ? "Link copied · " : "",
          el("a", { href: url, target: "_blank", rel: "noopener" }, url),
          ` · expires ${new Date(expiresAt).toLocaleDateString()}`
        );
      } catch (e) {
        status.textContent = e.message;
      } finally { shareBtn.disabled = false; }
    }
  }, "Share link");

  return el("div", { class: "action-bar-inner" },
    shareBtn,
    el("button", { type: "button", onclick: () => download(`${base}.json`, "application/json", JSON.stringify(data, null, 2)) }, "JSON"),
    el("button", { type: "button", onclick: () => download(`${base}.csv`, "text/csv", toCsv(data)) }, "CSV"),
    el("button", {
      type: "button",
      onclick: () => {
        printTarget.classList.add("mm-print-target");
        window.print();
        printTarget.classList.remove("mm-print-target");
      }
    }, "PDF"),
    status
  );
}

// For tools that render their own result (SMTP, DNS, Generator):
//   attachActions("dns", data, "dnsActions", "dnsResult")  -> shows Share/JSON/CSV/PDF under the result
//   clearActions("dnsActions")                              -> hides the bar (new run, error, validation failure)
export function attachActions(type, data, actionsId, printTargetId) {
  const bar = document.getElementById(actionsId);
  const target = document.getElementById(printTargetId);
  if (!bar || !target) return;
  bar.replaceChildren(resultActions(type, data, target));
}

export function clearActions(actionsId) {
  document.getElementById(actionsId)?.replaceChildren();
}

// Wires a tool: button click / Enter -> validate -> backend check -> request -> render -> action bar.
//   prepare(): validates inputs and returns the payload (throw Error for invalid input; no network call is made)
//   request(payload): performs the API call
export function bindTool({ button, enterOn = [], out, actions, type, busyMsg, prepare, request, render }) {
  if (!button || !out) return;
  const flow = createFlow(out.closest(".tool-panel"));

  const run = async () => {
    if (button.disabled) return;

    let payload;
    try {
      payload = prepare ? prepare() : undefined;
    } catch (e) {
      setResult(out, "error", e.message); // validation error: nothing was sent
      actions?.replaceChildren();
      return;
    }

    setBusy(button, true);
    actions?.replaceChildren();
    setResult(out, "waiting", busyMsg);
    flow.start();

    let backendReached = false;
    try {
      if (!(await checkBackend())) throw new Error("Unable to connect to the Node.js backend.");
      backendReached = true;
      flow.backendOk();
      const data = await request(payload);
      setResult(out, "");
      render(out, data);
      actions?.replaceChildren(resultActions(type, data, out));
      flow.done();
    } catch (e) {
      flow.fail(backendReached ? "flowSMTP" : "flowBackend"); // backend unreachable vs. check failed
      setResult(out, "error", e.message);
    } finally { setBusy(button, false); }
  };
  button.addEventListener("click", () => {
    void run();
  });

  enterOn.forEach((i) => i?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      void run();
    }
  }));
}

// Renders ?share=ID into #sharedTool / #sharedResult. renderers = { blacklist, score, tls }
export async function loadSharedFromUrl(renderers) {
  const id = new URLSearchParams(location.search).get("share");
  const card = document.getElementById("sharedTool");
  const out = document.getElementById("sharedResult");
  const meta = document.getElementById("sharedMeta");
  if (!id || !card || !out) return;

  card.classList.remove("hidden");
  setResult(out, "waiting", "Loading shared result…");
  try {
    const rec = await api(`/share/${encodeURIComponent(id)}`);
    meta.textContent = `${rec.type} result · expires ${new Date(rec.expiresAt).toLocaleString()}`;
    setResult(out, "");
    const render = renderers[rec.type];
    if (render) render(out, rec.data);
    else out.append(el("pre", {}, JSON.stringify(rec.data, null, 2)));
    card.scrollIntoView({ block: "start" });
  } catch (e) {
    setResult(out, "error", e.message);
  }
}
