import { $, escapeHtml } from "./utils.js";
import { startFlow, flowActive, flowSuccess, flowError, checkBackend } from "./flow.js";
import { attachActions, clearActions } from "./share.js";

const setState = (id, state, text) => {
  const el = $(id);
  if (!el) return;
  el.className = `stage ${state}`;
  if (text) el.querySelector("p")?.replaceChildren(document.createTextNode(text));
};

// Share/export the diagnostic OUTPUT only: never the username, password, sender, recipient list input or message body.
// Fire-and-forget by design: a failed share must never turn a finished test into an error, and
// attachActions may be sync or async, so both a throw and a rejection are contained here.
const shareResult = (status, title, data) => {
  void Promise.resolve()
    .then(() => attachActions("smtp", {
      status,
      title,
      host: $("smtpHost").value.trim(),
      port: Number($("smtpPort").value),
      security: $("smtpSecurity").value,
      ...data
    }, "smtpActions", "result"))
    .catch((error) => console.warn("Could not attach share actions:", error));
};

const showResult = (type, title, data = {}) => {
  const el = $("result");
  if (!el) return;
  el.className = `result ${type}`;
  el.innerHTML = `
    <div class="result-title">${escapeHtml(title)}</div>
    ${data.message ? `<div class="result-message">${escapeHtml(data.message)}</div>` : ""}
    ${data.error ? `<div class="result-message">${escapeHtml(data.error)}</div>` : ""}
    ${data.stage ? `<div class="technical-details">
      <div><span>Stage</span><strong>${escapeHtml(data.stage)}</strong></div>
      <div><span>Code</span><strong>${escapeHtml(data.code || "-")}</strong></div>
    </div>` : ""}
    ${data.messageId ? `<div class="success-details">
      <div><span>Message ID</span><strong>${escapeHtml(data.messageId)}</strong></div>
      <div><span>Accepted</span><strong>${escapeHtml(JSON.stringify(data.accepted || []))}</strong></div>
      <div><span>Rejected</span><strong>${escapeHtml(JSON.stringify(data.rejected || []))}</strong></div>
    </div>` : ""}
  `;
};

// Reachability check (shared) + sidebar status badge update (SMTP-specific UI).
// Never rejects: any failure (network error, missing badge elements) counts as "unreachable".
// Callers can therefore await it without a try/catch, or fire it with `void`.
async function backendHealth() {
  let ok = false;
  try {
    ok = Boolean(await checkBackend());
  } catch {
    ok = false;
  }
  const status = $("backendStatus");
  const dot = $("backendDot");
  if (status) status.textContent = ok ? "Connected" : "Unavailable";
  if (dot) dot.className = `status-dot ${ok ? "online" : "offline"}`;
  return ok;
}

export function initSMTP() {
  const button = $("testButton");
  if (!button) return;

  const security = $("smtpSecurity");
  const port = $("smtpPort");
  const password = $("smtpPassword");

  const toggle = $("togglePassword");
  toggle?.addEventListener("click", () => {
    const visible = password.type === "text";
    password.type = visible ? "password" : "text";
    toggle.textContent = visible ? "Show" : "Hide";
    // The visible word alone ("Show") doesn't say what is shown; keep the accessible name in sync.
    toggle.setAttribute("aria-label", visible ? "Show password" : "Hide password");
  });

  security?.addEventListener("change", () => {
    port.value = { starttls: 587, ssl: 465, plain: 25 }[security.value];
  });

  button.addEventListener("click", async () => {
    clearActions("smtpActions");
    const fields = [
      [$("smtpHost"), "SMTP host is required"],
      [port, "SMTP port is required"],
      [$("smtpUser"), "SMTP username is required"],
      [password, "SMTP password is required"],
      [$("fromEmail"), "From email is required"],
      [$("recipientEmail"), "Recipient email is required"],
      [$("message"), "Message is required"]
    ];

    for (const [field, message] of fields) {
      if (!field?.value.trim()) {
        showResult("error", "Validation Failed", { stage: "validation", error: message });
        field?.focus();
        return;
      }
    }

    button.disabled = true;
    button.textContent = "Testing SMTP...";

    startFlow();
    flowSuccess("flowFrontend");
    flowActive("flowBackend");
    setState("stageBackend", "active", "Checking backend...");

    if (!(await backendHealth())) {
      flowError("flowBackend");
      setState("stageBackend", "error", "Backend is not reachable.");
      showResult("error", "Backend Connection Failed", {
        stage: "backend_connection",
        error: "Unable to connect to the Node.js backend."
      });
      button.disabled = false;
      button.textContent = "Test SMTP & Send Email";
      return;
    }

    flowSuccess("flowBackend");
    setState("stageBackend", "success", "Request reached Node.js backend.");
    flowActive("flowSMTP");
    setState("stageSMTP", "active", "Connecting to SMTP server and verifying credentials...");

    try {
      const response = await fetch("/api/smtp/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          smtpHost: $("smtpHost").value.trim(),
          smtpPort: Number(port.value),
          smtpSecure: security.value === "ssl",
          smtpUser: $("smtpUser").value.trim(),
          smtpPassword: password.value,
          fromEmail: $("fromEmail").value.trim(),
          recipientName: $("recipientName")?.value.trim() || "",
          recipientEmail: $("recipientEmail").value.trim(),
          subject: $("subject")?.value.trim() || "SMTP Test Email",
          message: $("message").value
        })
      });

      // Rate limiter (429), proxy errors (502/503) and the like may not return JSON.
      const data = (await response.json().catch(() => null)) || {};

      // Only "email_sending" means the SMTP login worked and the send itself failed. Any other
      // failure (validation, host not allowed, rate limit, busy, auth, proxy error) is a failure
      // BEFORE credentials were verified, so it must not be reported as "credentials verified".
      if (!response.ok && data.stage !== "email_sending") {
        const isAuth = data.stage === "smtp_authentication";
        const isValidation = data.stage === "validation";
        const title = isAuth ? "SMTP Authentication Failed" : isValidation ? "Validation Failed" : "Request Failed";
        const failure = { ...data, error: data.error || `The server rejected the request (HTTP ${response.status}).` };
        flowError("flowSMTP");
        setState("stageSMTP", "error", isAuth ? "SMTP connection or authentication failed." : "The request was rejected before connecting to the SMTP server.");
        showResult("error", title, failure);
        if (isAuth) shareResult("error", title, failure);
        return;
      }

      flowSuccess("flowSMTP");
      setState("stageSMTP", "success", "SMTP credentials verified successfully.");
      flowActive("flowEmail");
      setState("stageEmail", "active", "Sending test email...");

      if (!response.ok) {
        flowError("flowEmail");
        setState("stageEmail", "error", "Email sending failed.");
        showResult("error", "Email Sending Failed", data);
        shareResult("error", "Email Sending Failed", data);
        return;
      }

      flowSuccess("flowEmail");
      setState("stageEmail", "success", "Test email was accepted by the SMTP server.");
      showResult("success", "SMTP Test Successful", data);
      shareResult("success", "SMTP Test Successful", data);
    } catch (error) {
      flowError("flowEmail");
      setState("stageEmail", "error", "Could not communicate with the backend.");
      showResult("error", "Request Failed", { stage: "frontend_request", error: error.message });
    } finally {
      button.disabled = false;
      button.textContent = "Test SMTP & Send Email";
    }
  });

  // Fire-and-forget: updates the sidebar badge. backendHealth() never rejects.
  void backendHealth();
}