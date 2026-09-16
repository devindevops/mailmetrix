import { $, escapeHtml } from "./utils.js";

const setState = (id, state, text) => {
  const el = $(id);
  if (!el) return;
  el.className = `stage ${state}`;
  if (text) el.querySelector("p")?.replaceChildren(document.createTextNode(text));
};

const setFlow = (id, state) => {
  const el = $(id);
  if (!el) return;
  el.classList.remove("active", "success", "error");
  el.classList.add(state);
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

async function backendHealth() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) throw new Error();
    await response.json();
    $("backendStatus").textContent = "Connected";
    $("backendDot").className = "status-dot online";
    return true;
  } catch {
    $("backendStatus").textContent = "Unavailable";
    $("backendDot").className = "status-dot offline";
    return false;
  }
}

export function initSMTP() {
  const button = $("testButton");
  if (!button) return;

  const security = $("smtpSecurity");
  const port = $("smtpPort");
  const password = $("smtpPassword");

  $("togglePassword")?.addEventListener("click", () => {
    const visible = password.type === "text";
    password.type = visible ? "password" : "text";
    $("togglePassword").textContent = visible ? "Show" : "Hide";
  });

  security?.addEventListener("change", () => {
    port.value = { starttls: 587, ssl: 465, plain: 25 }[security.value];
  });

  button.addEventListener("click", async () => {
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
    ["flowFrontend", "flowBackend", "flowSMTP", "flowEmail"].forEach((id) =>
      $(id)?.classList.remove("active", "success", "error")
    );

    setFlow("flowFrontend", "success");
    setState("stageBackend", "active", "Checking backend...");

    if (!(await backendHealth())) {
      setFlow("flowBackend", "error");
      setState("stageBackend", "error", "Backend is not reachable.");
      showResult("error", "Backend Connection Failed", {
        stage: "backend_connection",
        error: "Unable to connect to the Node.js backend."
      });
      button.disabled = false;
      button.textContent = "Test SMTP & Send Email";
      return;
    }

    setFlow("flowBackend", "success");
    setState("stageBackend", "success", "Request reached Node.js backend.");
    setFlow("flowSMTP", "active");
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

      const data = await response.json();

      if (!response.ok && data.stage === "smtp_authentication") {
        setFlow("flowSMTP", "error");
        setState("stageSMTP", "error", "SMTP connection or authentication failed.");
        showResult("error", "SMTP Authentication Failed", data);
        return;
      }

      setFlow("flowSMTP", "success");
      setState("stageSMTP", "success", "SMTP credentials verified successfully.");
      setFlow("flowEmail", "active");
      setState("stageEmail", "active", "Sending test email...");

      if (!response.ok) {
        setFlow("flowEmail", "error");
        setState("stageEmail", "error", "Email sending failed.");
        showResult("error", "Email Sending Failed", data);
        return;
      }

      setFlow("flowEmail", "success");
      setState("stageEmail", "success", "Test email was accepted by the SMTP server.");
      showResult("success", "SMTP Test Successful", data);
    } catch (error) {
      setFlow("flowEmail", "error");
      setState("stageEmail", "error", "Could not communicate with the backend.");
      showResult("error", "Request Failed", { stage: "frontend_request", error: error.message });
    } finally {
      button.disabled = false;
      button.textContent = "Test SMTP & Send Email";
    }
  });

  backendHealth();
}
