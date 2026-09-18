const crypto = require("crypto");

const SUPPORTED_BITS = [1024, 2048, 4096];
const DMARC_POLICIES = ["none", "quarantine", "reject"];
const ALIGNMENT = ["r", "s"];

function clean(value) {
  return typeof value === "string" ? value.trim() : "";
}

function validDomain(value) {
  const domain = clean(value).toLowerCase().replace(/\.$/, "");
  return domain && domain.length <= 253 &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)
    ? domain
    : null;
}

function validSelector(value) {
  const selector = clean(value);
  return selector && selector.length <= 63 && /^[a-zA-Z0-9._-]+$/.test(selector)
    ? selector
    : null;
}

function normalizePercentage(value, fallback = 100) {
  const number = Number(value);
  return Number.isInteger(number) && number >= 0 && number <= 100 ? number : fallback;
}

function normalizeReportInterval(value) {
  const number = Number(value);
  return Number.isInteger(number) && number >= 3600 && number <= 86400 ? number : 86400;
}

function generateDKIM(domain, selector, keySize) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: keySize,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  const publicKeyBase64 = publicKey.toString("base64");
  const dnsRecord = `${selector}._domainkey.${domain} IN TXT "v=DKIM1; k=rsa; p=${publicKeyBase64}"`;

  return {
    selector,
    domain,
    keySize,
    hostname: `${selector}._domainkey.${domain}`,
    publicKey: publicKeyBase64,
    privateKey: privateKey.trim(),
    dnsRecord
  };
}

function generateDMARC(domain, options) {
  const policy = DMARC_POLICIES.includes(options.policy) ? options.policy : "none";
  const subdomainPolicy = DMARC_POLICIES.includes(options.subdomainPolicy)
    ? options.subdomainPolicy
    : policy;
  const adkim = ALIGNMENT.includes(options.adkim) ? options.adkim : "r";
  const aspf = ALIGNMENT.includes(options.aspf) ? options.aspf : "r";
  const pct = normalizePercentage(options.pct);
  const fo = ["0", "1", "d", "s"].includes(options.fo) ? options.fo : "0";
  const ri = normalizeReportInterval(options.ri);
  const tags = [
    "v=DMARC1",
    `p=${policy}`,
    `sp=${subdomainPolicy}`,
    `adkim=${adkim}`,
    `aspf=${aspf}`,
    `pct=${pct}`,
    `fo=${fo}`,
    `ri=${ri}`
  ];

  const rua = clean(options.rua);
  const ruf = clean(options.ruf);
  if (rua) tags.push(`rua=${rua}`);
  if (ruf) tags.push(`ruf=${ruf}`);

  return {
    hostname: `_dmarc.${domain}`,
    record: `${tags.join("; ")};`,
    dnsRecord: `_dmarc.${domain} IN TXT "${tags.join("; ")};"`
  };
}

function generateRecords(input) {
  const domain = validDomain(input.domain);
  const selector = validSelector(input.selector || "MailMetrix");
  const keySize = Number(input.keySize || 2048);

  if (!domain) {
    return { httpStatus: 400, body: { success: false, error: "A valid domain is required." } };
  }
  if (!selector) {
    return { httpStatus: 400, body: { success: false, error: "Invalid DKIM selector." } };
  }
  if (!SUPPORTED_BITS.includes(keySize)) {
    return { httpStatus: 400, body: { success: false, error: "DKIM key size must be 1024, 2048 or 4096 bits." } };
  }

  const dkim = generateDKIM(domain, selector, keySize);
  const dmarc = generateDMARC(domain, input);

  return {
    httpStatus: 200,
    body: {
      success: true,
      dkim,
      dmarc,
      warning: "Keep the DKIM private key secret. Publish only the DKIM public key in DNS."
    }
  };
}

module.exports = { generateRecords };
