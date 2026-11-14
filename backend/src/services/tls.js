'use strict';
const net = require('net');
const tls = require('tls');
const { resolvePublic } = require('./netguard');

const ALLOWED_PORTS = new Set([25, 465, 587, 2525, 443, 993, 995]);
const IMPLICIT_PORTS = new Set([465, 443, 993, 995]);
const TIMEOUT = 10000;

const err = (msg, code) => Object.assign(new Error(msg), { code });

function openSocket(ip, port) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: ip, port });
    s.setTimeout(TIMEOUT);
    s.once('connect', () => { s.setTimeout(0); resolve(s); });
    s.once('timeout', () => { s.destroy(); reject(err('Connection timed out', 'TIMEOUT')); });
    s.once('error', (e) => { s.destroy(); reject(e); });
  });
}

function readReply(sock) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => { cleanup(); reject(err('SMTP server did not respond in time', 'TIMEOUT')); }, TIMEOUT);
    const onData = (d) => {
      buf += d.toString();
      if (buf.length > 8192) { cleanup(); return reject(err('Reply too large', 'BAD_REPLY')); }
      if (buf.endsWith('\r\n') && buf.split('\r\n').some((l) => /^\d{3} /.test(l))) { cleanup(); resolve(buf); }
    };
    const onErr = (e) => { cleanup(); reject(e); };
    const onClose = () => { cleanup(); reject(err('Connection closed by remote server', 'ECONNRESET')); };
    const cleanup = () => {
      clearTimeout(t);
      sock.off('data', onData);
      sock.off('error', onErr);
      sock.off('end', onClose);
      sock.off('close', onClose);
    };
    sock.on('data', onData);
    sock.on('error', onErr);
    sock.on('end', onClose);
    sock.on('close', onClose);
  });
}

async function secureConnect({ ip, host, port, mode, tlsOpts = {} }) {
  let plain;
  if (mode === 'starttls') {
    plain = await openSocket(ip, port);
    try {
      const greet = await readReply(plain);
      if (!/^220/.test(greet)) throw err(`Unexpected SMTP greeting: ${greet.trim().slice(0, 120)}`, 'BAD_GREETING');
      plain.write('EHLO mailprobe.local\r\n');
      const ehlo = await readReply(plain);
      if (!/^250[ -]STARTTLS/im.test(ehlo)) throw err('Server does not advertise STARTTLS', 'NO_STARTTLS');
      plain.write('STARTTLS\r\n');
      const ok = await readReply(plain);
      if (!/^220/.test(ok)) throw err(`STARTTLS rejected: ${ok.trim().slice(0, 120)}`, 'STARTTLS_REJECTED');
    } catch (e) {
      plain.destroy();
      throw e;
    }
  }
  return new Promise((resolve, reject) => {
    const sock = tls.connect({
      ...(plain ? { socket: plain } : { host: ip, port }),
      servername: net.isIP(host) ? undefined : host,
      // codeql[js/disabling-certificate-validation] Diagnostic scanner must connect to inspect untrusted/expired certificates and report validation status manually.
      // lgtm[js/disabling-certificate-validation]
      rejectUnauthorized: false, // we inspect, then report trust problems ourselves
      ...tlsOpts,
    });
    sock.setTimeout(TIMEOUT, () => {
      sock.destroy();
      if (plain) plain.destroy();
      reject(err('TLS handshake timed out', 'TIMEOUT'));
    });
    sock.once('secureConnect', () => { sock.setTimeout(0); resolve(sock); });
    sock.once('error', (e) => {
      sock.destroy();
      if (plain) plain.destroy();
      reject(e);
    });
  });
}

function summarizeCert(c) {
  return {
    subject: c.subject,
    issuer: c.issuer,
    validFrom: c.valid_from,
    validTo: c.valid_to,
    serialNumber: c.serialNumber,
    fingerprint256: c.fingerprint256,
    bits: c.bits,
    curve: c.asn1Curve || null,
    altNames: c.subjectaltname ? c.subjectaltname.split(', ').slice(0, 50) : [],
  };
}

function buildChain(leaf) {
  const out = [];
  const seen = new Set();
  let c = leaf;
  while (c && c.fingerprint256 && !seen.has(c.fingerprint256)) {
    seen.add(c.fingerprint256);
    out.push(summarizeCert(c));
    c = c.issuerCertificate;
  }
  return out;
}

async function probeVersions(base) {
  const versions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
  const results = await Promise.all(
    versions.map(async (v) => {
      try {
        const s = await secureConnect({ ...base, tlsOpts: { minVersion: v, maxVersion: v, ciphers: 'ALL:@SECLEVEL=0' } });
        s.destroy();
        return [v, true];
      } catch {
        return [v, false];
      }
    })
  );
  return Object.fromEntries(results);
}

async function inspect({ host, port = 25, mode, versions = false }) {
  host = String(host || '').trim().toLowerCase();
  port = Number(port);
  if (!ALLOWED_PORTS.has(port)) throw err(`Port must be one of: ${[...ALLOWED_PORTS].join(', ')}`, 'BAD_INPUT');
  mode = mode || (IMPLICIT_PORTS.has(port) ? 'implicit' : 'starttls');
  if (!['implicit', 'starttls'].includes(mode)) throw err('mode must be implicit or starttls', 'BAD_INPUT');

  const [ip] = await resolvePublic(host);
  const base = { ip, host, port, mode };
  const sock = await secureConnect(base);

  try {
    const leaf = sock.getPeerCertificate(true);
    if (!leaf || !leaf.fingerprint256) throw err('Server presented no certificate', 'NO_CERT');

    const chain = buildChain(leaf);
    const protocol = sock.getProtocol();
    const cipher = sock.getCipher();
    const validTo = new Date(leaf.valid_to);
    const daysRemaining = Math.floor((validTo - Date.now()) / 86400000);
    const idErr = net.isIP(host) ? null : tls.checkServerIdentity(host, leaf);
    const selfSigned = chain.length === 1 || leaf.issuerCertificate === leaf;

    const findings = [];
    const add = (severity, title, detail) => findings.push({ severity, title, detail });

    if (daysRemaining < 0) add('critical', 'Certificate expired', `Expired ${-daysRemaining} day(s) ago.`);
    else if (daysRemaining < 14) add('critical', 'Certificate expires very soon', `${daysRemaining} day(s) left.`);
    else if (daysRemaining < 30) add('warning', 'Certificate expires soon', `${daysRemaining} day(s) left.`);
    else add('ok', 'Certificate validity', `${daysRemaining} day(s) remaining.`);

    if (idErr) add('critical', 'Hostname mismatch', idErr.reason || idErr.message);
    else if (!net.isIP(host)) add('ok', 'Hostname matches certificate', host);

    if (!sock.authorized) {
      add(mode === 'starttls' && port === 25 ? 'warning' : 'critical', 'Certificate not trusted',
        `${sock.authorizationError || 'Unknown trust error'}${selfSigned ? ' (self-signed)' : ''}. ` +
        'Opportunistic TLS on port 25 tolerates this, but strict senders and MTA-STS will not.');
    } else add('ok', 'Certificate chain trusted', `${chain.length} certificate(s) in chain.`);

    if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol)) add('critical', 'Deprecated TLS version negotiated', protocol);
    else if (protocol === 'TLSv1.3') add('ok', 'Modern TLS', 'TLS 1.3 negotiated.');
    else add('ok', 'TLS version', `${protocol} negotiated.`);

    if (/RC4|3DES|NULL|EXPORT|MD5|DES-CBC/i.test(cipher.name)) add('critical', 'Weak cipher suite', cipher.name);
    if (!leaf.asn1Curve && leaf.bits && leaf.bits < 2048) add('warning', 'Weak RSA key', `${leaf.bits}-bit key (2048+ recommended).`);

    const result = {
      host, ip, port, mode,
      checkedAt: new Date().toISOString(),
      connection: {
        protocol,
        cipher: cipher.name,
        authorized: sock.authorized,
        authorizationError: sock.authorizationError ? String(sock.authorizationError) : null,
      },
      certificate: { ...summarizeCert(leaf), daysRemaining, selfSigned, hostnameMatch: !idErr },
      chain,
      findings,
    };
    sock.destroy();

    if (versions) {
      result.supportedVersions = await probeVersions(base);
      const legacy = ['TLSv1', 'TLSv1.1'].filter((v) => result.supportedVersions[v]);
      if (legacy.length) result.findings.push({ severity: 'warning', title: 'Legacy protocols enabled', detail: legacy.join(', ') });
    }
    return result;
  } finally {
    sock.destroy();
  }
}

module.exports = { inspect, ALLOWED_PORTS };
