import { $, escapeHtml } from "./utils.js";
import { startFlow, flowActive, flowSuccess, flowError } from "./flow.js";

function field(id) {
  return $(id)?.value.trim() || "";
}

export function initGenerator() {
  const button = $("generateAuthButton");
  const output = $("generatorResult");
  if (!button || !output) return;

  button.addEventListener("click", async () => {
    const domain = field("generatorDomain");
    if (!domain) {
      output.className = "result error";
      output.innerHTML = `<div class="result-title">Validation Failed</div><div class="result-message">Domain is required.</div>`;
      $("generatorDomain")?.focus();
      return;
    }

    const payload = {
      domain,
      allowA: $("spfAllowA")?.checked || false,
      allowMX: $("spfAllowMX")?.checked || false,
      ip4: field("spfIp4"),
      ip6: field("spfIp6"),
      includes: field("spfIncludes"),
      allMechanism: field("spfAllMechanism"),
      selector: field("dkimSelectorGenerator"),
      keySize: Number(field("dkimKeySize")),
      policy: field("dmarcPolicy"),
      subdomainPolicy: field("dmarcSubdomainPolicy"),
      adkim: field("dmarcAdkim"),
      aspf: field("dmarcAspf"),
      pct: Number(field("dmarcPct")),
      fo: field("dmarcFo"),
      rua: field("dmarcRua"),
      ruf: field("dmarcRuf")
    };

    button.disabled = true;
    button.innerHTML = `<span>Generating records...</span>`;
    startFlow();
    flowSuccess("flowFrontend");
    flowActive("flowBackend");
    output.className = "result waiting";
    output.textContent = `Generating SPF, ${payload.keySize}-bit RSA DKIM key pair, and DMARC record...`;

    try {
      const response = await fetch("/api/generator", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      flowSuccess("flowBackend");
      flowActive("flowSMTP");
      const data = await response.json();

      if (!response.ok) {
        flowError("flowSMTP");
        output.className = "result error";
        output.innerHTML = `<div class="result-title">Generation Failed</div><div class="result-message">${escapeHtml(data.error || "Unable to generate records.")}</div>`;
        return;
      }

      flowSuccess("flowSMTP");
      flowActive("flowEmail");

      const copyBlock = (label, value, extraClass = "") => `
        <div class="generator-output ${extraClass}">
          <div class="generator-output-header"><strong>${escapeHtml(label)}</strong><button type="button" class="copy-generator" data-copy="${encodeURIComponent(value)}">Copy</button></div>
          <pre>${escapeHtml(value)}</pre>
        </div>`;

      flowSuccess("flowEmail");
      output.className = "result success";
      output.innerHTML = `
        <div class="result-title">SPF, DKIM &amp; DMARC Generated</div>
        <div class="result-message">Records generated for <strong>${escapeHtml(data.dkim.domain)}</strong>.</div>
        <div class="generator-grid">
          ${copyBlock("SPF DNS Record", data.spf.dnsRecord)}
          ${copyBlock("DKIM DNS Record", data.dkim.dnsRecord)}
          ${copyBlock("DMARC DNS Record", data.dmarc.dnsRecord)}
          ${copyBlock("DKIM Public Key", data.dkim.publicKey)}
          ${copyBlock("DKIM Private Key — KEEP SECRET", data.dkim.privateKey, "private-key")}
        </div>
        <div class="generator-meta">
          <div><span>SPF Hostname </span><strong>${escapeHtml(data.spf.hostname)}</strong></div>
          <div><span>DKIM Hostname </span><strong>${escapeHtml(data.dkim.hostname)}</strong></div>
          <div><span>Key Size </span><strong>${escapeHtml(data.dkim.keySize)}-bit RSA</strong></div>
          <div><span>DMARC Hostname </span><strong>${escapeHtml(data.dmarc.hostname)}</strong></div>
        </div>
        <div class="generator-warning">${escapeHtml(data.warning)}</div>`;

      output.querySelectorAll(".copy-generator").forEach((copyButton) => {
        copyButton.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(decodeURIComponent(copyButton.dataset.copy));
            copyButton.textContent = "Copied";
            setTimeout(() => { copyButton.textContent = "Copy"; }, 1400);
          } catch {
            copyButton.textContent = "Copy failed";
          }
        });
      });
    } catch (error) {
      flowError("flowBackend");
      output.className = "result error";
      output.innerHTML = `<div class="result-title">Request Failed</div><div class="result-message">${escapeHtml(error.message)}</div>`;
    } finally {
      button.disabled = false;
      button.innerHTML = `<span>Generate SPF, DKIM &amp; DMARC</span><span class="button-arrow">→</span>`;
    }
  });
}