// Read-only views used when opening a shared link (?share=ID). Built with text nodes only.
import { el } from "./ui.js";

const label = (key) => key.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").replace(/^./, (c) => c.toUpperCase());
const badge = (status) => el("span", { class: `dns-badge ${String(status ?? "").replace(/[^a-z0-9_-]/gi, "")}` }, status ?? "unknown");
const pre = (text) => el("pre", {}, String(text));

/* ---------- SMTP ---------- */
export function renderSmtp(root, d) {
  const ok = d.status === "success";
  const row = (k, v) => (v === undefined || v === null || v === "" ? null : el("tr", {}, el("th", {}, k), el("td", {}, typeof v === "string" ? v : JSON.stringify(v))));
  root.replaceChildren(
    el("h3", {}, d.title || (ok ? "SMTP Test Successful" : "SMTP Test Failed")),
    d.message ? el("p", {}, d.message) : null,
    d.error ? el("p", {}, d.error) : null,
    el("table", {}, el("tbody", {},
      row("Result", ok ? "Success" : "Failed"),
      row("Host", d.host), row("Port", d.port), row("Security", d.security),
      row("Stage", d.stage), row("Code", d.code),
      row("Message ID", d.messageId), row("Accepted", d.accepted), row("Rejected", d.rejected)))
  );
}

/* ---------- DNS ---------- */
export function renderDns(root, d) {
  const mxRows = d.mx?.records?.length
    ? d.mx.records.map((r) => el("div", { class: "dns-mx-row" }, el("span", { class: "dns-mx-priority" }, r.priority), " ", el("span", { class: "dns-mx-host" }, r.exchange)))
    : [el("div", {}, "No MX records found.")];
  const record = (title, rec, missing) => el("div", { class: "dns-record" },
    el("div", { class: "dns-record-header" }, el("span", { class: "dns-record-title" }, title), badge(rec?.status)),
    rec?.record ? pre(rec.record) : el("div", {}, missing));

  root.replaceChildren(
    el("h3", {}, "DNS Check"),
    el("p", {}, "Email DNS records for ", el("strong", {}, d.domain), "."),
    el("div", { class: "dns-result-grid" },
      el("div", { class: "dns-record" },
        el("div", { class: "dns-record-header" }, el("span", { class: "dns-record-title" }, "MX Records"), badge(d.mx?.status)),
        el("div", { class: "dns-record-list" }, mxRows)),
      record("SPF", d.spf, "No SPF TXT record found."),
      record("DMARC", d.dmarc, "No DMARC record found."),
      d.dkim
        ? el("div", { class: "dns-record" },
            el("div", { class: "dns-record-header" }, el("span", { class: "dns-record-title" }, d.dkim.hostname || `DKIM (${d.dkim.selector})`), badge(d.dkim.status)),
            d.dkim.record ? pre(d.dkim.record) : el("div", {}, "No DKIM record found for this selector."))
        : null)
  );
}

/* ---------- Generator (same layout as the live result; the private key is never part of a share) ---------- */
export function renderGenerator(root, d) {
  const block = (title, value) => (value
    ? el("div", { class: "generator-output" },
        el("div", { class: "generator-output-header" },
          el("strong", {}, title),
          el("button", {
            type: "button",
            onclick: async (e) => {
              const btn = e.currentTarget;
              try { await navigator.clipboard.writeText(value); btn.textContent = "Copied"; } catch { btn.textContent = "Copy failed"; }
              setTimeout(() => { btn.textContent = "Copy"; }, 1400);
            }
          }, "Copy")),
        pre(value))
    : null);
  const meta = (k, v) => (v === undefined || v === null || v === "" ? null : el("div", {}, el("span", {}, `${k} `), el("strong", {}, String(v))));

  root.replaceChildren(
    el("div", { class: "result-title" }, "SPF, DKIM & DMARC Generated"),
    el("div", { class: "result-message" }, "Records generated for ", el("strong", {}, d.dkim?.domain || ""), "."),
    el("div", { class: "generator-grid" },
      block("SPF DNS Record", d.spf?.dnsRecord),
      block("DKIM DNS Record", d.dkim?.dnsRecord),
      block("DMARC DNS Record", d.dmarc?.dnsRecord),
      block("DKIM Public Key", d.dkim?.publicKey)),
    el("div", { class: "generator-meta" },
      meta("SPF Hostname", d.spf?.hostname),
      meta("DKIM Hostname", d.dkim?.hostname),
      meta("Key Size", d.dkim?.keySize ? `${d.dkim.keySize}-bit RSA` : ""),
      meta("DMARC Hostname", d.dmarc?.hostname)),
    el("div", { class: "generator-warning" }, "The DKIM private key is never included in shared or exported results. Generate your own key pair to get one.")
  );
}

/* ---------- Header analysis (same layout as the live result) ---------- */
export function renderHeaders(root, d) {
  const a = d.analysis || {};
  const auth = a.authentication || {};
  const hops = a.deliveryPath?.hops || [];
  const findings = d.findings || [];

  const authBadge = (status) => {
    const value = String(status || "not_found").toLowerCase();
    const cls = value === "pass" ? "ok" : ["fail", "softfail", "permerror", "temperror"].includes(value) ? "missing" : "info";
    return el("span", { class: `dns-badge ${cls}` }, value);
  };
  const stat = (k, v) => el("div", { class: "header-stat" }, el("span", {}, k), el("strong", {}, v || "Not found"));
  const meta = (k, v) => el("div", {}, el("span", {}, k), el("strong", {}, v || "Not found"));
  const sev = (s) => String(s || "info").toLowerCase().replace(/[^a-z]/g, "");

  root.replaceChildren(
    el("div", { class: "result-title" }, "Header Analysis"),
    el("div", { class: "result-message" }, "Parsed ", el("strong", {}, String(d.headerCount ?? "")), " headers. Raw header text is never included in shared results."),
    el("div", { class: "header-summary" },
      stat("From", a.from?.address), stat("Return-Path", a.returnPath?.address),
      stat("Message-ID", a.messageId), stat("Received Hops", String(a.deliveryPath?.hopCount ?? ""))),
    el("div", { class: "header-section" },
      el("h3", {}, "Authentication"),
      el("div", { class: "header-auth-grid" },
        el("div", {}, el("span", {}, "SPF"), authBadge(auth.spf)),
        el("div", {}, el("span", {}, "DKIM"), authBadge(auth.dkim)),
        el("div", {}, el("span", {}, "DMARC"), authBadge(auth.dmarc))),
      auth.authenticationResults ? pre(auth.authenticationResults) : el("p", {}, "No Authentication-Results header found.")),
    el("div", { class: "header-section" },
      el("h3", {}, "Message Metadata"),
      el("div", { class: "header-meta" },
        meta("Subject", a.subject), meta("Date", a.date), meta("Reply-To", a.replyTo?.address),
        meta("Content-Type", a.contentType), meta("MIME-Version", a.mimeVersion))),
    el("div", { class: "header-section" },
      el("h3", {}, "Delivery Path"),
      el("div", { class: "header-hops" }, hops.length
        ? hops.map((hop) => el("div", { class: "header-hop" },
            el("div", { class: "header-hop-number" }, String(hop.hop)),
            el("div", {},
              el("strong", {}, `${hop.from || "Unknown"}${hop.by ? ` → ${hop.by}` : ""}`),
              el("small", {}, `${hop.protocol || "Protocol not specified"}${hop.timestamp ? ` · ${hop.timestamp}` : ""}`))))
        : [el("div", {}, "No Received headers found.")])),
    el("div", { class: "header-section" },
      el("h3", {}, "Findings"),
      el("div", { class: "header-findings" }, findings.length
        ? findings.map((f) => el("div", { class: `header-finding ${sev(f.severity)}` }, el("strong", {}, String(f.severity || "").toUpperCase()), el("span", {}, f.message)))
        : [el("div", { class: "header-finding success" }, el("strong", {}, "OK"), el("span", {}, "No basic header issues were detected."))]))
  );
}