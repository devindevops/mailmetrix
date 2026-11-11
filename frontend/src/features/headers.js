import { $, escapeHtml } from "./utils.js";
import { startFlow, flowActive, flowSuccess, flowError } from "./flow.js";
import { attachActions, clearActions } from "./share.js";

const badge = (status) => {
  const value = String(status || "not_found").toLowerCase();
  const cls = value === "pass" ? "ok" :
    ["fail", "softfail", "permerror", "temperror"].includes(value) ? "missing" : "info";
  return `<span class="dns-badge ${cls}">${escapeHtml(value)}</span>`;
};

/* ---------- sharing: parsed analysis only, never the raw header text ---------- */

const EMAIL_RE = /[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi;

const maskEmails = (value) => {
  if (typeof value === "string") return value.replace(EMAIL_RE, "***@$1");
  if (Array.isArray(value)) return value.map(maskEmails);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskEmails(v)]));
  }
  return value;
};

// Only these three fields are ever shared/exported. `redact` hides the subject, display names
// and the username part of every email address (the domain is kept because it is what you debug with).
function shareable(data, redact) {
  const copy = JSON.parse(JSON.stringify({
    headerCount: data.headerCount,
    analysis: data.analysis,
    findings: data.findings
  }));
  if (!redact) return copy;

  const a = copy.analysis;
  if (a) {
    if (a.subject) a.subject = "[hidden]";
    ["from", "returnPath", "replyTo"].forEach((key) => {
      if (a[key] && typeof a[key] === "object" && a[key].name) a[key].name = "[hidden]";
    });
  }
  return maskEmails(copy);
}

function setupShare(data) {
  const bar = $("headerActions");
  if (!bar) return;

  let option = $("headerRedactOption");
  if (!option) {
    option = document.createElement("label");
    option.id = "headerRedactOption";
    option.className = "custom-checkbox";
    option.style.marginTop = "14px";

    const box = document.createElement("input");
    box.type = "checkbox";
    box.id = "headerRedact";
    box.checked = true;

    const text = document.createElement("span");
    text.textContent = "Hide subject, display names and email usernames in shared / exported results (PDF prints the result as displayed)";

    option.append(box, text);
    bar.before(option);
  }
  option.style.display = "inline-flex";

  const box = $("headerRedact");
  const attach = () => attachActions("headers", shareable(data, box.checked), "headerActions", "headerResult");
  box.onchange = attach;
  attach();
}

function clearShare() {
  clearActions("headerActions");
  const option = $("headerRedactOption");
  if (option) option.style.display = "none";
}

// Header fields end at the first blank line; everything after it is the message body.
// Only when the paste is large do we cut at that blank line (a whole message was probably pasted),
// so smaller pastes with stray blank lines are still analysed in full.
const LARGE_PASTE_BYTES = 90 * 1024;

function headerBlock(text) {
  if (new Blob([text]).size <= LARGE_PASTE_BYTES) return { headers: text, trimmed: false };
  const cut = text.search(/\r?\n[ \t]*\r?\n/);
  return cut > 0 ? { headers: text.slice(0, cut), trimmed: true } : { headers: text, trimmed: false };
}

export function initHeaders() {
  const button = $("analyzeHeadersButton");
  const input = $("emailHeaders");
  const result = $("headerResult");
  if (!button || !input || !result) return;

  button.addEventListener("click", async () => {
    const { headers, trimmed } = headerBlock(input.value.trim());
    clearShare();

    if (!headers) {
      result.className = "result error";
      result.innerHTML = `<div class="result-title">Headers Required</div><div class="result-message">Paste the raw email headers first.</div>`;
      input.focus();
      return;
    }

    button.disabled = true;
    button.textContent = "Analyzing Headers...";
    startFlow();
    flowSuccess("flowFrontend");
    flowActive("flowBackend");
    result.className = "result waiting";
    result.textContent = "Parsing email headers...";

    try {
      const response = await fetch("/api/headers/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ headers })
      });

      flowSuccess("flowBackend");
      flowActive("flowSMTP");
      const data = await response.json();

      if (!response.ok) {
        flowError("flowSMTP");
        result.className = "result error";
        const message = response.status === 413
          ? "The pasted text is too large. Paste only the email headers (everything above the first blank line), not the whole message."
          : data.error || "Unable to analyze the supplied headers.";
        result.innerHTML = `<div class="result-title">Header Analysis Failed</div><div class="result-message">${escapeHtml(message)}</div>`;
        return;
      }

      flowSuccess("flowSMTP");
      flowActive("flowEmail");

      const a = data.analysis;
      const auth = a.authentication;

      const hops = a.deliveryPath.hops.length
        ? a.deliveryPath.hops.map((hop) => `<div class="header-hop"><div class="header-hop-number">${escapeHtml(hop.hop)}</div><div><strong>${escapeHtml(hop.from || "Unknown")}${hop.by ? ` → ${escapeHtml(hop.by)}` : ""}</strong><small>${escapeHtml(hop.protocol || "Protocol not specified")}${hop.timestamp ? ` · ${escapeHtml(hop.timestamp)}` : ""}</small></div></div>`).join("")
        : "<div>No Received headers found.</div>";

      const findings = data.findings.length
        ? data.findings.map((f) => `<div class="header-finding ${escapeHtml(f.severity)}"><strong>${escapeHtml(f.severity.toUpperCase())}</strong><span>${escapeHtml(f.message)}</span></div>`).join("")
        : `<div class="header-finding success"><strong>OK</strong><span>No basic header issues were detected.</span></div>`;

      flowSuccess("flowEmail");
      result.className = "result success";
      result.innerHTML = `
        <div class="result-title">Header Analysis Complete</div>
        <div class="result-message">Parsed <strong>${escapeHtml(data.headerCount)}</strong> headers.${trimmed ? " The message body was ignored." : ""}</div>
        <div class="header-summary">
          <div class="header-stat"><span>From </span><strong>${escapeHtml(a.from.address || "Not found")}</strong></div>
          <div class="header-stat"><span>Return-Path </span><strong>${escapeHtml(a.returnPath.address || "Not found")}</strong></div>
          <div class="header-stat"><span>Message-ID </span><strong>${escapeHtml(a.messageId || "Not found")}</strong></div>
          <div class="header-stat"><span>Received Hops </span><strong>${escapeHtml(a.deliveryPath.hopCount)}</strong></div>
        </div>
        <div class="header-section"><h3>Authentication</h3>
          <div class="header-auth-grid"><div><span>SPF</span>${badge(auth.spf)}</div><div><span>DKIM</span>${badge(auth.dkim)}</div><div><span>DMARC</span>${badge(auth.dmarc)}</div></div>
          ${auth.authenticationResults ? `<pre>${escapeHtml(auth.authenticationResults)}</pre>` : "<p>No Authentication-Results header found.</p>"}
        </div>
        <div class="header-section"><h3>Message Metadata</h3>
          <div class="header-meta">
            <div><span>Subject </span><strong>${escapeHtml(a.subject || "Not found")}</strong></div>
            <div><span>Date </span><strong>${escapeHtml(a.date || "Not found")}</strong></div>
            <div><span>Reply-To </span><strong>${escapeHtml(a.replyTo.address || "Not found")}</strong></div>
            <div><span>Content-Type </span><strong>${escapeHtml(a.contentType || "Not found")}</strong></div>
            <div><span>MIME-Version </span><strong>${escapeHtml(a.mimeVersion || "Not found")}</strong></div>
          </div>
        </div>
        <div class="header-section"><h3>Delivery Path</h3><div class="header-hops">${hops}</div></div>
        <div class="header-section"><h3>Findings</h3><div class="header-findings">${findings}</div></div>`;

      setupShare(data);
    } catch (error) {
      flowError("flowBackend");
      result.className = "result error";
      result.innerHTML = `<div class="result-title">Request Failed</div><div class="result-message">${escapeHtml(error.message)}</div>`;
    } finally {
      button.disabled = false;
      button.textContent = "Analyze Email Headers";
    }
  });
}