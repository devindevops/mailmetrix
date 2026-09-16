import { $, escapeHtml } from "./utils.js";

export function initDNS() {
  const button = $("dnsButton");
  const domain = $("domain");
  const output = $("dnsResult");
  if (!button || !domain || !output) return;

  button.addEventListener("click", async () => {
    const value = domain.value.trim();

    if (!value) {
      output.className = "result error";
      output.innerHTML = `<div class="result-title">Validation Failed</div><div class="result-message">Domain is required.</div>`;
      domain.focus();
      return;
    }

    button.disabled = true;
    button.textContent = "Checking DNS...";
    output.className = "result waiting";
    output.textContent = "Resolving MX, SPF and DMARC records...";

    try {
      const response = await fetch(`/api/dns/check?domain=${encodeURIComponent(value)}`);
      const data = await response.json();

      if (!response.ok) {
        output.className = "result error";
        output.innerHTML = `<div class="result-title">DNS Check Failed</div><div class="result-message">${escapeHtml(data.error || "DNS lookup failed.")}</div>`;
        return;
      }

      const mx = data.mx.records.length
        ? data.mx.records.map((r) => `<div class="dns-mx-row"><span class="dns-mx-priority">${escapeHtml(r.priority)}</span><span class="dns-mx-host">${escapeHtml(r.exchange)}</span></div>`).join("")
        : "<div>No MX records found.</div>";

      const record = (value, missing) =>
        value ? `<pre>${escapeHtml(value)}</pre>` : `<div>${escapeHtml(missing)}</div>`;

      output.className = "result success";
      output.innerHTML = `
        <div class="result-title">DNS Check Complete</div>
        <div class="result-message">Email DNS records for <strong>${escapeHtml(data.domain)}</strong>.</div>
        <div class="dns-result-grid">
          <div class="dns-record"><div class="dns-record-header"><span class="dns-record-title">MX Records</span><span class="dns-badge ${escapeHtml(data.mx.status)}">${escapeHtml(data.mx.status)}</span></div><div class="dns-record-list">${mx}</div></div>
          <div class="dns-record"><div class="dns-record-header"><span class="dns-record-title">SPF</span><span class="dns-badge ${escapeHtml(data.spf.status)}">${escapeHtml(data.spf.status)}</span></div>${record(data.spf.record, "No SPF TXT record found.")}</div>
          <div class="dns-record"><div class="dns-record-header"><span class="dns-record-title">DMARC</span><span class="dns-badge ${escapeHtml(data.dmarc.status)}">${escapeHtml(data.dmarc.status)}</span></div>${record(data.dmarc.record, "No DMARC record found.")}</div>
          <div class="dns-record">
            <div class="dns-record-header"><span class="dns-record-title">DKIM</span><span class="dns-badge info">Selector Required</span></div>
            <div class="tool-description">Enter a DKIM selector to check its DNS record.</div>
            <div class="dns-selector"><div class="form-group"><label for="dkimSelector">DKIM Selector</label><input id="dkimSelector" type="text" placeholder="google" autocomplete="off" /></div><button id="dkimButton" class="test-button" type="button">Check DKIM</button></div>
            <div id="dkimResult"></div>
          </div>
        </div>`;

      $("dkimButton").addEventListener("click", async () => {
        const selector = $("dkimSelector").value.trim();
        const dkimButton = $("dkimButton");
        const dkimOutput = $("dkimResult");
        if (!selector) {
          $("dkimSelector").focus();
          return;
        }

        dkimButton.disabled = true;
        dkimButton.textContent = "Checking...";

        try {
          const response = await fetch(`/api/dns/dkim?domain=${encodeURIComponent(data.domain)}&selector=${encodeURIComponent(selector)}`);
          const dkim = await response.json();

          if (!response.ok) {
            dkimOutput.innerHTML = `<div class="result error" style="margin-top:16px;">${escapeHtml(dkim.error || "DKIM lookup failed.")}</div>`;
            return;
          }

          dkimOutput.innerHTML = `<div class="dns-record" style="margin-top:16px;"><div class="dns-record-header"><span class="dns-record-title">${escapeHtml(dkim.hostname)}</span><span class="dns-badge ${escapeHtml(dkim.status)}">${escapeHtml(dkim.status)}</span></div>${dkim.record ? `<pre>${escapeHtml(dkim.record)}</pre>` : "<div>No DKIM record found for this selector.</div>"}</div>`;
        } catch (error) {
          dkimOutput.innerHTML = `<div class="result error" style="margin-top:16px;">${escapeHtml(error.message)}</div>`;
        } finally {
          dkimButton.disabled = false;
          dkimButton.textContent = "Check DKIM";
        }
      });
    } catch (error) {
      output.className = "result error";
      output.innerHTML = `<div class="result-title">Request Failed</div><div class="result-message">${escapeHtml(error.message)}</div>`;
    } finally {
      button.disabled = false;
      button.textContent = "Check Email DNS";
    }
  });
}
