'use strict';

const net = require('net');
const tls = require('tls');

const { resolvePublic } = require('./netguard');

const ALLOWED_PORTS = new Set([
  25,
  465,
  587,
  2525,
  443,
  993,
  995,
]);

const IMPLICIT_PORTS = new Set([
  465,
  443,
  993,
  995,
]);

const TIMEOUT = 10000;
const MAX_REPLY_SIZE = 8192;

const err = (msg, code) =>
  Object.assign(new Error(msg), { code });

// --------------------------------------------------
// Socket connection
// --------------------------------------------------

function openSocket(ip, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({
      host: ip,
      port,
      family: net.isIP(ip),
    });

    let settled = false;

    const cleanup = () => {
      socket.removeListener('connect', onConnect);
      socket.removeListener('timeout', onTimeout);
      socket.removeListener('error', onError);
    };

    const fail = (error) => {
      if (settled) return;

      settled = true;
      cleanup();
      socket.destroy();
      reject(error);
    };

    const onConnect = () => {
      if (settled) return;

      settled = true;
      cleanup();

      socket.setTimeout(0);
      resolve(socket);
    };

    const onTimeout = () => {
      fail(err('Connection timed out', 'TIMEOUT'));
    };

    const onError = (error) => {
      fail(error);
    };

    socket.setTimeout(TIMEOUT);

    socket.once('connect', onConnect);
    socket.once('timeout', onTimeout);
    socket.once('error', onError);
  });
}

// --------------------------------------------------
// SMTP response reader
// --------------------------------------------------

function readReply(socket) {
  return new Promise((resolve, reject) => {
    let buffer = '';

    const timer = setTimeout(() => {
      cleanup();
      reject(
        err('SMTP server did not respond in time', 'TIMEOUT')
      );
    }, TIMEOUT);

    const cleanup = () => {
      clearTimeout(timer);

      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('end', onClose);
      socket.off('close', onClose);
    };

    const onData = (data) => {
      buffer += data.toString('utf8');

      if (buffer.length > MAX_REPLY_SIZE) {
        cleanup();

        reject(
          err('SMTP reply too large', 'BAD_REPLY')
        );

        return;
      }

      // SMTP multiline responses terminate with:
      // 250 <message>
      // Previous lines normally use 250-.
      const lines = buffer.split('\r\n');

      const complete = lines.some((line) =>
        /^\d{3} /.test(line)
      );

      if (buffer.endsWith('\r\n') && complete) {
        cleanup();
        resolve(buffer);
      }
    };

    const onError = (error) => {
      cleanup();
      reject(error);
    };

    const onClose = () => {
      cleanup();

      reject(
        err(
          'Connection closed by remote server',
          'ECONNRESET'
        )
      );
    };

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('end', onClose);
    socket.on('close', onClose);
  });
}

// --------------------------------------------------
// TLS connection
// --------------------------------------------------

async function secureConnect({
  ip,
  host,
  port,
  mode,
  tlsOpts = {},
}) {
  let plain;

  if (mode === 'starttls') {
    plain = await openSocket(ip, port);

    try {
      const greeting = await readReply(plain);

      if (!/^220(?:[ -])/m.test(greeting)) {
        throw err(
          `Unexpected SMTP greeting: ${greeting.trim().slice(0, 120)}`,
          'BAD_GREETING'
        );
      }

      plain.write('EHLO mailprobe.local\r\n');

      const ehlo = await readReply(plain);

      if (!/^250[ -]STARTTLS/im.test(ehlo)) {
        throw err(
          'Server does not advertise STARTTLS',
          'NO_STARTTLS'
        );
      }

      plain.write('STARTTLS\r\n');

      const response = await readReply(plain);

      if (!/^220(?:[ -])/m.test(response)) {
        throw err(
          `STARTTLS rejected: ${response.trim().slice(0, 120)}`,
          'STARTTLS_REJECTED'
        );
      }
    } catch (error) {
      plain.destroy();
      throw error;
    }
  }

  return new Promise((resolve, reject) => {
    let settled = false;

    const options = {
      ...(plain
        ? { socket: plain }
        : {
            host: ip,
            port,
            family: net.isIP(ip),
          }),

      // SNI is not applicable to IP address literals.
      servername: net.isIP(host) ? undefined : host,

      ...tlsOpts,

      // Intentionally disabled because this is a diagnostic
      // scanner that must inspect untrusted certificates.
      //
      // Certificate trust is evaluated separately below.
      //
      // codeql[js/disabling-certificate-validation]
      // lgtm[js/disabling-certificate-validation]
      rejectUnauthorized: false,
    };

    const socket = tls.connect(options);

    const cleanup = () => {
      socket.removeListener('secureConnect', onSecure);
      socket.removeListener('timeout', onTimeout);
      socket.removeListener('error', onError);
    };

    const fail = (error) => {
      if (settled) return;

      settled = true;
      cleanup();

      socket.destroy();

      if (plain) {
        plain.destroy();
      }

      reject(error);
    };

    const onSecure = () => {
      if (settled) return;

      settled = true;
      cleanup();

      socket.setTimeout(0);
      resolve(socket);
    };

    const onTimeout = () => {
      fail(
        err('TLS handshake timed out', 'TIMEOUT')
      );
    };

    const onError = (error) => {
      fail(error);
    };

    socket.setTimeout(TIMEOUT);

    socket.once('secureConnect', onSecure);
    socket.once('timeout', onTimeout);
    socket.once('error', onError);
  });
}

// --------------------------------------------------
// Certificate summary
// --------------------------------------------------

function summarizeCert(cert) {
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    bits: cert.bits,
    curve: cert.asn1Curve || null,

    altNames: cert.subjectaltname
      ? cert.subjectaltname.split(', ').slice(0, 50)
      : [],
  };
}

// --------------------------------------------------
// Certificate chain
// --------------------------------------------------

function buildChain(leaf) {
  const chain = [];
  const seen = new Set();

  let cert = leaf;

  while (
    cert &&
    cert.fingerprint256 &&
    !seen.has(cert.fingerprint256)
  ) {
    seen.add(cert.fingerprint256);

    chain.push(summarizeCert(cert));

    cert = cert.issuerCertificate;
  }

  return chain;
}

// --------------------------------------------------
// TLS version probing
// --------------------------------------------------

async function probeVersions(base) {
  const versions = [
    'TLSv1',
    'TLSv1.1',
    'TLSv1.2',
    'TLSv1.3',
  ];

  const results = await Promise.all(
    versions.map(async (version) => {
      try {
        const socket = await secureConnect({
          ...base,

          tlsOpts: {
            minVersion: version,
            maxVersion: version,
            ciphers: 'ALL:@SECLEVEL=0',
          },
        });

        socket.destroy();

        return [version, true];
      } catch {
        return [version, false];
      }
    })
  );

  return Object.fromEntries(results);
}

// --------------------------------------------------
// Input validation
// --------------------------------------------------

function validatePort(value) {
  if (value === undefined || value === null || value === '') {
    return 25;
  }

  const port = Number(value);

  if (!Number.isInteger(port) || !ALLOWED_PORTS.has(port)) {
    throw err(
      `Port must be one of: ${[...ALLOWED_PORTS].join(', ')}`,
      'BAD_INPUT'
    );
  }

  return port;
}

// --------------------------------------------------
// TLS inspection
// --------------------------------------------------

async function inspect({
  host,
  port = 25,
  mode,
  versions = false,
}) {
  // Hostname validation
  if (typeof host !== 'string') {
    throw err(
      'A valid hostname or IP address is required',
      'BAD_INPUT'
    );
  }

  host = host.trim().toLowerCase();

  if (!host || host.length > 253) {
    throw err('Invalid hostname', 'BAD_INPUT');
  }

  // Port validation
  port = validatePort(port);

  // Connection mode validation
  mode = mode || (
    IMPLICIT_PORTS.has(port)
      ? 'implicit'
      : 'starttls'
  );

  if (!['implicit', 'starttls'].includes(mode)) {
    throw err(
      'mode must be implicit or starttls',
      'BAD_INPUT'
    );
  }

  // ------------------------------------------------
  // SSRF protection
  // ------------------------------------------------

  // Resolve and validate ALL addresses before connecting.
  // Never pass the original hostname to the network layer.

  const addresses = await resolvePublic(host);

  if (!addresses.length) {
    throw err('No public IP addresses available', 'BLOCKED');
  }

  // Use a validated IP address.
  // This prevents a second DNS lookup during connection.

  const ip = addresses[0];

  const base = {
    ip,
    host,
    port,
    mode,
  };

  const socket = await secureConnect(base);

  try {
    const leaf = socket.getPeerCertificate(true);

    if (!leaf || !leaf.fingerprint256) {
      throw err(
        'Server presented no certificate',
        'NO_CERT'
      );
    }

    const chain = buildChain(leaf);

    const protocol = socket.getProtocol();
    const cipher = socket.getCipher();

    const validTo = new Date(leaf.valid_to);

    const daysRemaining = Math.floor(
      (validTo.getTime() - Date.now()) / 86400000
    );

    // Check identity for both DNS names and IP addresses.
    // SNI is still disabled for IP literals.

    const identityError = tls.checkServerIdentity(
      host,
      leaf
    );

    const selfSigned =
      chain.length === 1 ||
      leaf.issuerCertificate === leaf;

    const findings = [];

    const add = (severity, title, detail) => {
      findings.push({
        severity,
        title,
        detail,
      });
    };

    // ----------------------------------------------
    // Certificate expiration
    // ----------------------------------------------

    if (daysRemaining < 0) {
      add(
        'critical',
        'Certificate expired',
        `Expired ${-daysRemaining} day(s) ago.`
      );
    } else if (daysRemaining < 14) {
      add(
        'critical',
        'Certificate expires very soon',
        `${daysRemaining} day(s) left.`
      );
    } else if (daysRemaining < 30) {
      add(
        'warning',
        'Certificate expires soon',
        `${daysRemaining} day(s) left.`
      );
    } else {
      add(
        'ok',
        'Certificate validity',
        `${daysRemaining} day(s) remaining.`
      );
    }

    // ----------------------------------------------
    // Hostname verification
    // ----------------------------------------------

    if (identityError) {
      add(
        'critical',
        'Hostname mismatch',
        identityError.reason || identityError.message
      );
    } else {
      add(
        'ok',
        'Hostname matches certificate',
        host
      );
    }

    // ----------------------------------------------
    // Certificate trust
    // ----------------------------------------------

    if (!socket.authorized) {
      add(
        mode === 'starttls' && port === 25
          ? 'warning'
          : 'critical',
        'Certificate not trusted',

        `${socket.authorizationError || 'Unknown trust error'}` +
        `${selfSigned ? ' (self-signed)' : ''}. ` +
        'Opportunistic TLS on port 25 tolerates this, ' +
        'but strict senders and MTA-STS will not.'
      );
    } else {
      add(
        'ok',
        'Certificate chain trusted',
        `${chain.length} certificate(s) in chain.`
      );
    }

    // ----------------------------------------------
    // TLS protocol
    // ----------------------------------------------

    if (
      ['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol)
    ) {
      add(
        'critical',
        'Deprecated TLS version negotiated',
        protocol
      );
    } else if (protocol === 'TLSv1.3') {
      add(
        'ok',
        'Modern TLS',
        'TLS 1.3 negotiated.'
      );
    } else {
      add(
        'ok',
        'TLS version',
        `${protocol} negotiated.`
      );
    }

    // ----------------------------------------------
    // Cipher strength
    // ----------------------------------------------

    if (
      cipher &&
      /RC4|3DES|NULL|EXPORT|MD5|DES-CBC/i.test(cipher.name)
    ) {
      add(
        'critical',
        'Weak cipher suite',
        cipher.name
      );
    }

    // ----------------------------------------------
    // Public key strength
    // ----------------------------------------------

    if (
      !leaf.asn1Curve &&
      leaf.bits &&
      leaf.bits < 2048
    ) {
      add(
        'warning',
        'Weak RSA key',
        `${leaf.bits}-bit key (2048+ recommended).`
      );
    }

    // ----------------------------------------------
    // Result
    // ----------------------------------------------

    const result = {
      host,
      ip,
      port,
      mode,

      checkedAt: new Date().toISOString(),

      connection: {
        protocol,
        cipher: cipher ? cipher.name : null,
        authorized: socket.authorized,

        authorizationError: socket.authorizationError
          ? String(socket.authorizationError)
          : null,
      },

      certificate: {
        ...summarizeCert(leaf),
        daysRemaining,
        selfSigned,
        hostnameMatch: !identityError,
      },

      chain,
      findings,
    };

    socket.destroy();

    // ----------------------------------------------
    // Optional TLS version probing
    // ----------------------------------------------

    if (versions === true) {
      result.supportedVersions = await probeVersions(base);

      const legacy = [
        'TLSv1',
        'TLSv1.1',
      ].filter(
        (version) => result.supportedVersions[version]
      );

      if (legacy.length) {
        result.findings.push({
          severity: 'warning',
          title: 'Legacy protocols enabled',
          detail: legacy.join(', '),
        });
      }
    }

    return result;
  } finally {
    socket.destroy();
  }
}

module.exports = {
  inspect,
  ALLOWED_PORTS,
};