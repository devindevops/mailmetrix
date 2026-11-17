import { el, post, badge } from "./ui.js";
import { bindTool } from "./share.js";

const row = (k, v) => el("tr", {}, el("th", {}, k), el("td", {}, v ?? "—"));
const name = (o) => (o ? o.CN || o.O || Object.values(o).join(", ") : "—");

export function renderTls(root, d) {
  const c = d.certificate;
  const v = d.supportedVersions;
  root.replaceChildren(
    el("h3", {}, `${d.host}:${d.port}`),
    el("ul", { class: "mm-findings" }, d.findings.map((f) =>
      el("li", {}, badge(f.severity, f.severity), " ", el("strong", {}, f.title), f.detail ? ` — ${f.detail}` : ""))),
    el("h4", {}, "Connection"),
    el("table", {}, el("tbody", {},
      row("IP", d.ip),
      row("Mode", d.mode),
      row("Protocol", d.connection.protocol),
      row("Cipher", d.connection.cipher),
      row("Trusted", d.connection.authorized ? "Yes" : `No (${d.connection.authorizationError})`),
      v ? row("Versions", Object.entries(v).map(([k, ok]) => `${k}: ${ok ? "yes" : "no"}`).join(" · ")) : null)),
    el("h4", {}, "Certificate"),
    el("table", {}, el("tbody", {},
      row("Subject", name(c.subject)),
      row("Issuer", name(c.issuer)),
      row("Valid from", c.validFrom),
      row("Valid to", `${c.validTo} (${c.daysRemaining} days)`),
      row("Key", c.curve ? `EC ${c.curve}` : `RSA ${c.bits} bits`),
      row("SANs", c.altNames.join(", ") || "—"),
      row("SHA-256", c.fingerprint256),
      row("Serial", c.serialNumber))),
    el("h4", {}, "Chain"),
    el("ol", {}, d.chain.map((x) => el("li", {}, `${name(x.subject)} (issued by ${name(x.issuer)})`)))
  );
}

export function initTls() {
  const host = document.getElementById("tlsHost");
  bindTool({
    button: document.getElementById("tlsButton"),
    enterOn: [host],
    out: document.getElementById("tlsResult"),
    actions: document.getElementById("tlsActions"),
    type: "tls",
    busyMsg: "Connecting and negotiating TLS…",
    request: async () => {
      const h = host.value.trim();
      if (!h) throw new Error("Enter a mail server hostname.");
      return post("/tls", {
        host: h,
        port: Number(document.getElementById("tlsPort").value),
        versions: document.getElementById("tlsVersions").checked
      });
    },
    render: renderTls
  });
}
