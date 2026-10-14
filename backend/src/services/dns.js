const dns = require("node:dns").promises;

function normalizeDomain(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "");
}

function validateDomain(domain) {
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/i.test(domain);
}

async function resolveTxtSafe(name) {
  try {
    return (await dns.resolveTxt(name)).map((parts) => parts.join(""));
  } catch (error) {
    if (["ENODATA", "ENOTFOUND", "SERVFAIL"].includes(error.code)) return [];
    throw error;
  }
}

async function resolveMxSafe(domain) {
  try {
    return await dns.resolveMx(domain);
  } catch (error) {
    if (["ENODATA", "ENOTFOUND", "SERVFAIL"].includes(error.code)) return [];
    throw error;
  }
}

async function checkEmailDNS(inputDomain) {
  const domain = normalizeDomain(inputDomain);

  if (!validateDomain(domain)) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "validation",
        error: "Enter a valid domain name."
      }
    };
  }

  try {
    const [mx, txtRecords, dmarcRecords] = await Promise.all([
      resolveMxSafe(domain),
      resolveTxtSafe(domain),
      resolveTxtSafe(`_dmarc.${domain}`)
    ]);

    const spfRecord =
      txtRecords.find((record) => /^v=spf1(?:\s|$)/i.test(record)) || null;

    const dmarcRecord =
      dmarcRecords.find((record) =>
        /^v=dmarc1(?:\s|;|$)/i.test(record)
      ) || null;

    return {
      httpStatus: 200,
      body: {
        success: true,
        domain,
        mx: {
          status: mx.length ? "ok" : "missing",
          records: mx.sort((a, b) => a.priority - b.priority)
        },
        spf: {
          status: spfRecord ? "ok" : "missing",
          record: spfRecord
        },
        dmarc: {
          status: dmarcRecord ? "ok" : "missing",
          record: dmarcRecord
        },
        dkim: {
          status: "selector_required",
          message: "Provide a DKIM selector to check the DKIM record."
        }
      }
    };
  } catch (error) {
    return {
      httpStatus: 502,
      body: {
        success: false,
        stage: "dns_lookup",
        error: "DNS lookup failed.",
        code: error.code || null
      }
    };
  }
}

async function checkDKIM(inputDomain, inputSelector) {
  const domain = normalizeDomain(inputDomain);
  const selector = String(inputSelector || "").trim().toLowerCase();

  if (!validateDomain(domain)) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "validation",
        error: "Enter a valid domain name."
      }
    };
  }

  if (!selector || !/^[a-z0-9._-]+$/i.test(selector)) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "validation",
        error: "Enter a valid DKIM selector."
      }
    };
  }

  const hostname = `${selector}._domainkey.${domain}`;

  try {
    const records = await resolveTxtSafe(hostname);
    const record =
      records.find((value) => /^v=dkim1(?:\s|;|$)/i.test(value)) ||
      records[0] ||
      null;

    return {
      httpStatus: 200,
      body: {
        success: true,
        domain,
        selector,
        hostname,
        status: record ? "ok" : "missing",
        record
      }
    };
  } catch (error) {
    return {
      httpStatus: 502,
      body: {
        success: false,
        stage: "dns_lookup",
        error: "DKIM DNS lookup failed.",
        code: error.code || null
      }
    };
  }
}

module.exports = { checkEmailDNS, checkDKIM };
