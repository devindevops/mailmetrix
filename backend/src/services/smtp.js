const nodemailer = require("nodemailer");
const dns = require("node:dns").promises;
const net = require("node:net");
// Single canonical IP blocklist shared with tls.js / score.js / blacklist.js.
const { isPrivateIp, isValidHostname } = require("./netguard");

const required = (value) =>
  typeof value === "string" && value.trim().length > 0;

const requiredPort = (value) =>
  value !== undefined &&
  value !== null &&
  String(value).trim().length > 0;

const validationError = (error) => ({
  httpStatus: 400,
  body: { success: false, stage: "validation", error }
});

/* ------------------------------------------------------------------ */
/* SSRF protection (SEC-01 / CWE-918)                                  */
/* ------------------------------------------------------------------ */

// Standard mail submission ports. Override with SMTP_ALLOWED_PORTS="25,465,587"
const ALLOWED_PORTS = new Set(
  (process.env.SMTP_ALLOWED_PORTS || "25,465,587,2525")
    .split(",")
    .map((p) => Number(p.trim()))
    .filter(Number.isInteger)
);

// Optional escape hatch for a trusted internal relay: SMTP_ALLOWED_HOSTS="mail.corp.local"
// NOTE: an allowlisted hostname bypasses the IP check. Only list names you control.
const ALLOWED_INTERNAL_HOSTS = new Set(
  (process.env.SMTP_ALLOWED_HOSTS || "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
);

// Kept as an export for backwards compatibility; the logic lives in netguard.js.
const isBlockedIp = isPrivateIp;

// One message for "does not resolve", "invalid name" and "resolves to a private IP", so the
// response cannot be used to enumerate internal DNS names (e.g. Docker service names).
const HOST_DENIED = "SMTP host is not allowed or could not be resolved";

/**
 * Resolve the host once, validate EVERY returned address, and return a
 * single vetted IP to connect to. Returns { ip } or { error }.
 */
async function resolveSafeHost(host) {
  const hostname = host.toLowerCase();
  const trustedInternal = ALLOWED_INTERNAL_HOSTS.has(hostname);

  let addresses;
  if (net.isIP(host)) {
    addresses = [{ address: host }];
  } else {
    // Public names must be dotted FQDNs (blocks single-label names like "redis" or "db").
    if (!trustedInternal && !isValidHostname(host)) {
      return { error: HOST_DENIED };
    }
    try {
      addresses = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
      return { error: HOST_DENIED };
    }
  }

  if (!addresses.length) {
    return { error: HOST_DENIED };
  }

  if (!trustedInternal) {
    // Reject if ANY record is internal; prevents mixed public/private answers.
    for (const { address } of addresses) {
      if (isBlockedIp(address)) {
        return { error: HOST_DENIED };
      }
    }
  }

  return { ip: addresses[0].address };
}

/* ------------------------------------------------------------------ */
/* Email abuse guardrails (SEC-04 / CWE-306)                           */
/*                                                                     */
/* Authentication itself belongs at the perimeter (reverse-proxy auth, */
/* Cloudflare Access, Authelia, Tailscale...). These controls limit    */
/* what an unauthenticated caller can do if that perimeter is missing. */
/* ------------------------------------------------------------------ */

// Optional: restrict who can receive test emails. Comma-separated.
//   ALLOWED_RECIPIENT_DOMAINS="example.com,*.corp.example.com"
// "example.com" matches that domain only; "*.example.com" matches subdomains.
const ALLOWED_RECIPIENT_DOMAINS = (process.env.ALLOWED_RECIPIENT_DOMAINS || "")
  .split(",")
  .map((d) => d.trim().toLowerCase())
  .filter(Boolean);

// Optional: the test email may only be sent to the From address itself
// (a "send a test to myself" workflow). Limits each request to one mailbox.
const ENFORCE_TEST_RECIPIENT =
  String(process.env.ENFORCE_TEST_RECIPIENT || "").toLowerCase() === "true";

const MAX_HOST_LENGTH = 253;
const MAX_USER_LENGTH = 256;
const MAX_PASSWORD_LENGTH = 1024;
const MAX_SUBJECT_LENGTH = 200;
const MAX_MESSAGE_LENGTH = 5000;
const MAX_DISPLAY_NAME_LENGTH = 100;

const EMAIL_LOCAL_PART = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$/;
const EMAIL_DOMAIN =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/**
 * Accept exactly ONE plain address (no display name, no lists, no quoting).
 * Rejects "a@x.com, b@y.com", "Name <a@x.com>", quoted locals, CR/LF, etc.,
 * so a single request cannot fan out to many recipients or smuggle in extra
 * ones past the domain policy. Returns { address, domain } or null.
 */
function parseSingleEmail(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 254) return null;

  const at = trimmed.lastIndexOf("@");
  if (at < 1) return null;

  const local = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1).toLowerCase();

  if (!EMAIL_LOCAL_PART.test(local)) return null;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return null;
  }
  if (!EMAIL_DOMAIN.test(domain)) return null;

  return { address: `${local}@${domain}`, domain };
}

function recipientDomainAllowed(domain) {
  if (!ALLOWED_RECIPIENT_DOMAINS.length) return true;

  return ALLOWED_RECIPIENT_DOMAINS.some((rule) =>
    rule.startsWith("*.")
      ? domain.endsWith(rule.slice(1)) && domain.length > rule.length - 1
      : domain === rule
  );
}

// Strip control characters (incl. CR/LF) from single-line header values.
const stripControls = (value) => value.replace(/[\u0000-\u001f\u007f]/g, " ");

// Display names are passed as structured fields to Nodemailer (which encodes
// them safely); here we only strip control characters and cap the length.
function cleanDisplayName(value) {
  if (!required(value)) return "";
  return stripControls(value).trim().slice(0, MAX_DISPLAY_NAME_LENGTH);
}

/* ------------------------------------------------------------------ */

async function testSMTP(data = {}) {
  const {
    smtpHost,
    smtpPort,
    smtpSecure,
    smtpUser,
    smtpPassword,
    fromEmail,
    fromName,
    recipientName,
    recipientEmail,
    subject,
    message
  } = data;

  const requiredFields = [
    [smtpHost, "SMTP host is required"],
    [smtpUser, "SMTP username is required"],
    [smtpPassword, "SMTP password is required"],
    [fromEmail, "From email is required"],
    [recipientEmail, "Recipient email is required"],
    [message, "Message is required"]
  ];

  for (const [value, error] of requiredFields) {
    if (!required(value)) {
      return validationError(error);
    }
  }

  if (smtpHost.trim().length > MAX_HOST_LENGTH) {
    return validationError("SMTP host is too long");
  }
  if (smtpUser.length > MAX_USER_LENGTH) {
    return validationError("SMTP username is too long");
  }
  if (smtpPassword.length > MAX_PASSWORD_LENGTH) {
    return validationError("SMTP password is too long");
  }

  if (!requiredPort(smtpPort)) {
    return validationError("SMTP port is required");
  }

  const port = Number(smtpPort);
  const secure = smtpSecure === true || smtpSecure === "true";

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return validationError("Invalid SMTP port");
  }

  // Port allowlist (checked before any DNS lookup or socket)
  if (!ALLOWED_PORTS.has(port)) {
    return validationError(
      `SMTP port must be one of: ${[...ALLOWED_PORTS].join(", ")}`
    );
  }

  // --- Message guardrails (all checked before any DNS lookup or socket) ---

  const from = parseSingleEmail(fromEmail);
  if (!from) {
    return validationError("From email must be a single valid email address");
  }

  const recipient = parseSingleEmail(recipientEmail);
  if (!recipient) {
    return validationError(
      "Recipient email must be a single valid email address"
    );
  }

  if (!recipientDomainAllowed(recipient.domain)) {
    return validationError("Recipient domain is not allowed");
  }

  if (ENFORCE_TEST_RECIPIENT && recipient.address !== from.address) {
    return validationError(
      "Test emails can only be sent to the From address on this server"
    );
  }

  // Single-line header value: strip CR/LF and other control characters first.
  const cleanSubject = required(subject) ? stripControls(subject).trim() : "";

  if (cleanSubject.length > MAX_SUBJECT_LENGTH) {
    return validationError(
      `Subject must be ${MAX_SUBJECT_LENGTH} characters or fewer`
    );
  }

  if (message.length > MAX_MESSAGE_LENGTH) {
    return validationError(
      `Message must be ${MAX_MESSAGE_LENGTH} characters or fewer`
    );
  }

  const smtp = {
    host: smtpHost.trim(),
    port,
    secure,
    username: smtpUser.trim(),
    fromEmail: from.address
  };

  // Resolve + validate BEFORE any socket is opened.
  const resolved = await resolveSafeHost(smtp.host);
  if (resolved.error) {
    return validationError(resolved.error);
  }

  const transporter = nodemailer.createTransport({
    host: resolved.ip,                       // connect to the vetted IP (prevents DNS rebinding)
    port: smtp.port,
    secure: smtp.secure,
    auth: { user: smtp.username, pass: smtpPassword },
    tls: net.isIP(smtp.host)
      ? {}
      : { servername: smtp.host },           // SNI + cert validation against the real hostname
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });

  try {
    await transporter.verify();
  } catch (error) {
    // Only surface SMTP-protocol-level details (the server spoke SMTP and
    // rejected us). Network-level failures are collapsed to avoid a
    // port-scanning oracle.
    const isProtocolError = Boolean(error.responseCode);
    return {
      httpStatus: 502,
      body: {
        success: false,
        stage: "smtp_authentication",
        error: isProtocolError
          ? error.message
          : "Unable to connect to the SMTP server",
        ...(isProtocolError && {
          code: error.code || null,
          command: error.command || null,
          response: error.response || null,
          responseCode: error.responseCode || null
        }),
        smtp
      }
    };
  }

  try {
    const recipientDisplayName = cleanDisplayName(recipientName);

    const info = await transporter.sendMail({
      from: {
        name: cleanDisplayName(fromName) || "MailMetrix",
        address: from.address
      },
      // Structured address object: the display name can never inject extra
      // recipients or headers.
      to: recipientDisplayName
        ? { name: recipientDisplayName, address: recipient.address }
        : recipient.address,
      subject: cleanSubject || "SMTP Test Email",
      text: message
    });

    return {
      httpStatus: 200,
      body: {
        success: true,
        stage: "email_sent",
        message:
          "SMTP credentials are valid and the test email was sent successfully.",
        messageId: info.messageId,
        response: info.response,
        accepted: info.accepted,
        rejected: info.rejected,
        smtp
      }
    };
  } catch (error) {
    const isProtocolError = Boolean(error.responseCode);
    return {
      httpStatus: 500,
      body: {
        success: false,
        stage: "email_sending",
        error: isProtocolError ? error.message : "Failed to send the test email",
        ...(isProtocolError && {
          code: error.code || null,
          command: error.command || null,
          response: error.response || null,
          responseCode: error.responseCode || null
        }),
        smtp
      }
    };
  }
}

module.exports = { testSMTP, isBlockedIp, parseSingleEmail };