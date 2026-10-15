const crypto = require("crypto");

const SUPPORTED_BITS = [1024, 2048, 4096];
const DMARC_POLICIES = ["none", "quarantine", "reject"];
const ALIGNMENT = ["r", "s"];
const SPF_ALL_MECHANISMS = ["-all", "~all", "?all", "+all"];

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

function generateSPF(domain, options) {
  const mechanisms = ["v=spf1"];

  // Optional flags for A and MX mechanisms
  if (options.allowA) {
    mechanisms.push("a");
  }
  if (options.allowMX) {
    mechanisms.push("mx");
  }

  // Handle IPv4 addresses/subnets (string or array)
  if (options.ip4) {
    const ip4List = Array.isArray(options.ip4)
      ? options.ip4
      : options.ip4.split(/[\s,]+/).map(i => clean(i)).filter(Boolean);

    for (const ip of ip4List) {
      if (ip) mechanisms.push(`ip4:${ip}`);
    }
  }

  // Handle IPv6 addresses/subnets (string or array)
  if (options.ip6) {
    const ip6List = Array.isArray(options.ip6)
      ? options.ip6
      : options.ip6.split(/[\s,]+/).map(i => clean(i)).filter(Boolean);

    for (const ip of ip6List) {
      if (ip) mechanisms.push(`ip6:${ip}`);
    }
  }

  // Handle included third-party domains (e.g., _spf.google.com)
  const incRaw = options.includes || options.include;
  if (incRaw) {
    const incList = Array.isArray(incRaw)
      ? incRaw
      : incRaw.split(/[\s,]+/).map(i => clean(i)).filter(Boolean);

    for (const inc of incList) {
      const validInc = validDomain(inc);
      if (validInc) {
        mechanisms.push(`include:${validInc}`);
      }
    }
  }

  // Final all mechanism (default to ~all for softfail)
  const allVal = SPF_ALL_MECHANISMS.includes(options.allMechanism) ? options.allMechanism : "~all";
  mechanisms.push(allVal);

  const record = mechanisms.join(" ");

  return {
    hostname: domain,
    record,
    dnsRecord: `${domain} IN TXT "${record}"`
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

  const spf = generateSPF(domain, input);
  const dkim = generateDKIM(domain, selector, keySize);
  const dmarc = generateDMARC(domain, input);

  return {
    httpStatus: 200,
    body: {
      success: true,
      spf,
      dkim,
      dmarc,
      warning: "Keep the DKIM private key secret. Publish only the SPF, DKIM public key, and DMARC records in DNS."
    }
  };
}

module.exports = { generateRecords };