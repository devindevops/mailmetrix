function unfoldHeaders(rawHeaders) {
  return rawHeaders.replace(/\r?\n[ \t]+/g, " ");
}

function parseHeaders(rawHeaders) {
  const headers = [];

  for (const line of unfoldHeaders(rawHeaders).split(/\r?\n/)) {
    if (!line.trim()) continue;

    const separator = line.indexOf(":");
    if (separator <= 0) continue;

    headers.push({
      name: line.slice(0, separator).trim(),
      value: line.slice(separator + 1).trim()
    });
  }

  return headers;
}

function getHeaderValues(headers, name) {
  return headers
    .filter((header) => header.name.toLowerCase() === name.toLowerCase())
    .map((header) => header.value);
}

function getHeaderValue(headers, name) {
  return getHeaderValues(headers, name)[0] || null;
}

function parseAuthenticationResults(value) {
  if (!value) return {};

  const result = {};

  for (const match of value.matchAll(
    /\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z0-9_-]+)/gi
  )) {
    result[match[1].toLowerCase()] = match[2].toLowerCase();
  }

  return result;
}

function parseAddress(value) {
  if (!value) return null;
  const match = value.match(/<([^>]+)>/);
  return (match ? match[1] : value).trim() || null;
}

function parseDomain(address) {
  const normalized = parseAddress(address);
  if (!normalized || !normalized.includes("@")) return null;
  return normalized.split("@").pop().toLowerCase();
}

function analyzeReceivedHeaders(values) {
  return values.map((value, index) => ({
    hop: index + 1,
    from: value.match(/\bfrom\s+([^\s(]+)/i)?.[1] || null,
    by: value.match(/\bby\s+([^\s(]+)/i)?.[1] || null,
    protocol: value.match(/\bwith\s+([^\s;]+)/i)?.[1] || null,
    timestamp:
      value.match(
        /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?[\s\S]*?(?:\+|-)\d{4}/i
      )?.[0] || null,
    raw: value
  }));
}

function analyzeHeaders(input) {
  const rawHeaders = String(input || "").trim();

  if (!rawHeaders) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "validation",
        error: "Email headers are required."
      }
    };
  }

  if (rawHeaders.length > 100000) {
    return {
      httpStatus: 413,
      body: {
        success: false,
        stage: "validation",
        error: "Email headers exceed the 100 KB limit."
      }
    };
  }

  const headers = parseHeaders(rawHeaders);

  if (!headers.length) {
    return {
      httpStatus: 400,
      body: {
        success: false,
        stage: "parsing",
        error: "No valid email headers were found."
      }
    };
  }

  const authHeader = getHeaderValue(headers, "Authentication-Results");
  const auth = parseAuthenticationResults(authHeader);
  const from = getHeaderValue(headers, "From");
  const returnPath = getHeaderValue(headers, "Return-Path");
  const replyTo = getHeaderValue(headers, "Reply-To");
  const received = analyzeReceivedHeaders(getHeaderValues(headers, "Received"));

  const findings = [];

  if (!from) findings.push({
    severity: "warning",
    message: "The From header is missing."
  });

  if (!returnPath) findings.push({
    severity: "info",
    message: "No Return-Path header was found."
  });

  if (!getHeaderValue(headers, "Date")) findings.push({
    severity: "warning",
    message: "The Date header is missing."
  });

  if (!getHeaderValue(headers, "Message-ID")) findings.push({
    severity: "info",
    message: "The Message-ID header is missing."
  });

  if (!authHeader) {
    findings.push({
      severity: "info",
      message:
        "No Authentication-Results header was found. Authentication status cannot be determined from these headers alone."
    });
  } else {
    for (const method of ["spf", "dkim", "dmarc"]) {
      if (auth[method] === "fail") findings.push({
        severity: "error",
        message: `${method.toUpperCase()} authentication reports fail.`
      });

      if (auth[method] === "softfail") findings.push({
        severity: "warning",
        message: `${method.toUpperCase()} authentication reports softfail.`
      });
    }
  }

  return {
    httpStatus: 200,
    body: {
      success: true,
      headerCount: headers.length,
      analysis: {
        from: {
          value: from,
          address: parseAddress(from),
          domain: parseDomain(from)
        },
        returnPath: {
          value: returnPath,
          address: parseAddress(returnPath),
          domain: parseDomain(returnPath)
        },
        replyTo: {
          value: replyTo,
          address: parseAddress(replyTo),
          domain: parseDomain(replyTo)
        },
        messageId: getHeaderValue(headers, "Message-ID"),
        subject: getHeaderValue(headers, "Subject"),
        date: getHeaderValue(headers, "Date"),
        contentType: getHeaderValue(headers, "Content-Type"),
        mimeVersion: getHeaderValue(headers, "MIME-Version"),
        authentication: {
          authenticationResults: authHeader,
          spf: auth.spf || "not_found",
          dkim: auth.dkim || "not_found",
          dmarc: auth.dmarc || "not_found"
        },
        deliveryPath: {
          hopCount: received.length,
          hops: received
        }
      },
      findings
    }
  };
}

module.exports = { analyzeHeaders };
