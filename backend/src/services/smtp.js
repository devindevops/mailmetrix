const nodemailer = require("nodemailer");
const dns = require("node:dns").promises;
const net = require("node:net");

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

const blocked = new net.BlockList();

// IPv4
[
  ["0.0.0.0", 8],          // "this" network
  ["10.0.0.0", 8],         // NOSONAR: S1313 - RFC 1918
  ["100.64.0.0", 10],      // NOSONAR: S1313 - CGNAT (often used for internal infra)
  ["127.0.0.0", 8],        // loopback
  ["169.254.0.0", 16],     // NOSONAR: S1313 - link-local + cloud metadata
  ["172.16.0.0", 12],      // NOSONAR: S1313 - RFC 1918
  ["192.0.0.0", 24],       // NOSONAR: S1313 - IETF protocol assignments
  ["192.0.2.0", 24],       // NOSONAR: S1313 - TEST-NET-1
  ["192.168.0.0", 16],     // NOSONAR: S1313 - RFC 1918
  ["198.18.0.0", 15],      // NOSONAR: S1313 - benchmarking
  ["198.51.100.0", 24],    // NOSONAR: S1313 - TEST-NET-2
  ["203.0.113.0", 24],     // NOSONAR: S1313 - TEST-NET-3
  ["224.0.0.0", 4],        // NOSONAR: S1313 - multicast
  ["240.0.0.0", 4]         // NOSONAR: S1313 - reserved (incl. 255.255.255.255)
].forEach(([addr, prefix]) => blocked.addSubnet(addr, prefix, "ipv4"));

// IPv6
blocked.addAddress("::", "ipv6");              // unspecified
blocked.addAddress("::1", "ipv6");             // loopback
[
  ["fc00::", 7],       // NOSONAR: S1313 - unique local
  ["fe80::", 10],      // NOSONAR: S1313 - link-local
  ["ff00::", 8],       // NOSONAR: S1313 - multicast
  ["64:ff9b::", 96],   // NOSONAR: S1313 - NAT64 (can embed private IPv4)
  ["2001:db8::", 32]   // NOSONAR: S1313 - documentation
].forEach(([addr, prefix]) => blocked.addSubnet(addr, prefix, "ipv6"));

function isBlockedIp(ip) {
  const family = net.isIP(ip);
  if (!family) return true; // not a valid IP -> fail closed

  // Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1, or hex form ::ffff:7f00:1)
  if (family === 6) {
    const lower = ip.toLowerCase();

    const dotted = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (dotted) return isBlockedIp(dotted[1]);

    const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = Number.parseInt(hex[1], 16);
      const lo = Number.parseInt(hex[2], 16);
      return isBlockedIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }

    return blocked.check(ip, "ipv6");
  }

  return blocked.check(ip, "ipv4");
}

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
    try {
      addresses = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
      return { error: "SMTP host could not be resolved" };
    }
  }

  if (!addresses.length) {
    return { error: "SMTP host could not be resolved" };
  }

  if (!trustedInternal) {
    // Reject if ANY record is internal; prevents mixed public/private answers.
    for (const { address } of addresses) {
      if (isBlockedIp(address)) {
        return { error: "SMTP host is not allowed" };
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

// Display names are passed as structured fields to Nodemailer (which encodes
// them safely); here we only strip control characters and cap the length.
function cleanDisplayName(value) {
  if (!required(value)) return "";
  return value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim()
    .slice(0, MAX_DISPLAY_NAME_LENGTH);
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

  if (required(subject) && subject.trim().length > MAX_SUBJECT_LENGTH) {
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
      subject: required(subject) ? subject.trim() : "SMTP Test Email",
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