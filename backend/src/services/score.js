'use strict';
// Deliverability score. Self-contained: swap the DNS helpers for your services/dns.js if you prefer.
const dns = require('dns');
const { isValidHostname } = require('./netguard');
const blacklist = require('./blacklist');
const tlsService = require('./tls');

const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'mail', 'dkim', 'smtp', 'mandrill', 'mailjet', 'amazonses', 'zoho', 'sendgrid', 'em', 'protonmail'];

const txt = async (name) => {
  try { return (await resolver.resolveTxt(name)).map((c) => c.join('')); } catch { return []; }
};
const safe = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };

const mk = (id, label, max, points, status, detail, fix) => ({ id, label, max, points: Math.round(points * 10) / 10, status, detail, fix: fix || null });

async function getMx(domain) {
  const mx = await safe(() => resolver.resolveMx(domain), []);
  return mx.filter((m) => m.exchange && m.exchange !== '.').sort((a, b) => a.priority - b.priority);
}

async function mxIps(mx) {
  const out = [];
  for (const m of mx.slice(0, 3)) {
    const ips = await safe(() => resolver.resolve4(m.exchange), []);
    for (const ip of ips.slice(0, 2)) out.push({ host: m.exchange, ip });
  }
  return out;
}

async function spfLookups(domain, depth = 0, seen = new Set()) {
  if (depth > 10 || seen.has(domain)) return 0;
  seen.add(domain);
  const rec = (await txt(domain)).find((t) => /^v=spf1\b/i.test(t));
  if (!rec) return 0;
  let n = 0;
  for (const term of rec.split(/\s+/).slice(1)) {
    const m = term.replace(/^[+\-~?]/, '');
    if (/^include:/i.test(m)) n += 1 + (await spfLookups(m.slice(8), depth + 1, seen));
    else if (/^redirect=/i.test(m)) n += 1 + (await spfLookups(m.slice(9), depth + 1, seen));
    else if (/^(a|mx)(:|\/|$)/i.test(m) || /^(ptr|exists:)/i.test(m)) n += 1;
  }
  return n;
}

async function checkMx(domain, mx) {
  if (!mx.length) return mk('mx', 'MX records', 10, 0, 'fail', 'No MX records found.', 'Add MX records pointing at your mail servers.');
  if (mx.length === 1) return mk('mx', 'MX records', 10, 8, 'warn', `1 MX record (${mx[0].exchange}).`, 'Add a secondary MX for redundancy.');
  return mk('mx', 'MX records', 10, 10, 'pass', `${mx.length} MX records, primary ${mx[0].exchange}.`);
}

async function checkSpf(domain) {
  const recs = (await txt(domain)).filter((t) => /^v=spf1\b/i.test(t));
  if (!recs.length) return mk('spf', 'SPF', 20, 0, 'fail', 'No SPF record found.', 'Publish a TXT record such as "v=spf1 include:<provider> -all".');
  if (recs.length > 1) return mk('spf', 'SPF', 20, 4, 'fail', `${recs.length} SPF records found; receivers will return PermError.`, 'Merge into a single SPF record.');
  const rec = recs[0];
  const lookups = await spfLookups(domain);
  let pts = 20;
  const notes = [];
  let status = 'pass';
  let fix = null;
  if (/\s\+all\b/i.test(rec) || /\sall\b/i.test(rec) && !/[-~?]all/i.test(rec)) { pts = 2; status = 'fail'; notes.push('Allows any sender (+all).'); fix = 'Replace with -all or ~all.'; }
  else if (/\s\?all\b/i.test(rec)) { pts -= 10; status = 'warn'; notes.push('Neutral policy (?all).'); fix = 'Use ~all or -all.'; }
  else if (/\s~all\b/i.test(rec)) { pts -= 3; notes.push('Soft fail (~all).'); }
  else if (/\s-all\b/i.test(rec)) notes.push('Hard fail (-all).');
  else if (!/redirect=/i.test(rec)) { pts -= 8; status = 'warn'; notes.push('No "all" mechanism.'); fix = 'End the record with -all or ~all.'; }
  if (lookups > 10) { pts = Math.min(pts, 6); status = 'fail'; notes.push(`${lookups} DNS lookups (limit is 10).`); fix = 'Flatten includes to stay at 10 lookups or fewer.'; }
  else if (lookups >= 8) { pts -= 2; if (status === 'pass') status = 'warn'; notes.push(`${lookups}/10 DNS lookups.`); }
  else notes.push(`${lookups}/10 DNS lookups.`);
  return mk('spf', 'SPF', 20, Math.max(pts, 0), status, notes.join(' '), fix);
}

async function checkDkim(domain, selector) {
  const selectors = selector ? [selector] : DKIM_SELECTORS;
  const found = [];
  await Promise.all(selectors.map(async (s) => {
    const r = await txt(`${s}._domainkey.${domain}`);
    if (r.some((t) => /v=DKIM1|p=/i.test(t))) found.push(s);
  }));
  if (found.length) return mk('dkim', 'DKIM', 15, 15, 'pass', `Key found for selector(s): ${found.join(', ')}.`);
  return selector
    ? mk('dkim', 'DKIM', 15, 0, 'fail', `No DKIM key at ${selector}._domainkey.${domain}.`, 'Publish your DKIM public key or check the selector name.')
    : mk('dkim', 'DKIM', 15, 7, 'warn', 'No key found on common selectors (yours may use a custom one).', 'Re-run with your DKIM selector to verify.');
}

async function checkDmarc(domain) {
  const rec = (await txt(`_dmarc.${domain}`)).find((t) => /^v=DMARC1/i.test(t));
  if (!rec) return mk('dmarc', 'DMARC', 20, 0, 'fail', 'No DMARC record found.', 'Add _dmarc TXT: "v=DMARC1; p=none; rua=mailto:dmarc@' + domain + '".');
  const p = (rec.match(/\bp=(\w+)/i) || [])[1]?.toLowerCase();
  const hasRua = /\brua=/i.test(rec);
  let pts = { reject: 20, quarantine: 17, none: 9 }[p] ?? 5;
  if (!hasRua) pts -= 2;
  const status = p === 'reject' || p === 'quarantine' ? 'pass' : 'warn';
  const fix = p === 'none' ? 'Move to p=quarantine, then p=reject once reports look clean.' : !hasRua ? 'Add an rua= address to receive aggregate reports.' : null;
  return mk('dmarc', 'DMARC', 20, Math.max(pts, 0), status, `Policy p=${p || 'unknown'}${hasRua ? ', reporting enabled' : ', no reporting address'}.`, fix);
}

async function checkRdns(ips) {
  if (!ips.length) return mk('rdns', 'Reverse DNS (FCrDNS)', 10, 0, 'skip', 'No MX IPs to test.');
  let ok = 0;
  const bad = [];
  for (const { ip } of ips) {
    const names = await safe(() => resolver.reverse(ip), []);
    let good = false;
    for (const n of names) {
      const fwd = await safe(() => resolver.resolve4(n), []);
      if (fwd.includes(ip)) { good = true; break; }
    }
    if (good) ok += 1; else bad.push(ip);
  }
  const pts = (ok / ips.length) * 10;
  if (!bad.length) return mk('rdns', 'Reverse DNS (FCrDNS)', 10, 10, 'pass', `All ${ips.length} MX IP(s) have matching PTR and A records.`);
  return mk('rdns', 'Reverse DNS (FCrDNS)', 10, pts, ok ? 'warn' : 'fail', `No forward-confirmed PTR for: ${bad.join(', ')}.`, 'Ask your host to set a PTR that resolves back to the same IP.');
}

async function checkBlacklist(ips) {
  if (!ips.length) return mk('blacklist', 'Blacklists', 10, 0, 'skip', 'No MX IPs to test.');
  const unique = [...new Set(ips.map((i) => i.ip))].slice(0, 3);
  const results = await Promise.all(unique.map((ip) => safe(() => blacklist.checkIp(ip), null)));
  const flat = results.filter(Boolean).flatMap((r) => r.results.filter((x) => x.status === 'listed').map((x) => `${r.target} on ${x.name}`));
  const known = results.filter(Boolean).flatMap((r) => r.results).filter((x) => x.status !== 'unknown').length;
  if (!known) return mk('blacklist', 'Blacklists', 10, 0, 'skip', 'Blacklist servers did not answer (resolver may be blocked).');
  if (!flat.length) return mk('blacklist', 'Blacklists', 10, 10, 'pass', `MX IPs are clean on ${known} lookups.`);
  return mk('blacklist', 'Blacklists', 10, Math.max(0, 10 - flat.length * 5), 'fail', `Listed: ${flat.join('; ')}.`, 'Request delisting and fix the cause (compromised account, open relay, bad reputation).');
}

async function checkMtaSts(domain) {
  const rec = (await txt(`_mta-sts.${domain}`)).find((t) => /^v=STSv1/i.test(t));
  return rec
    ? mk('mtasts', 'MTA-STS', 5, 5, 'pass', 'MTA-STS record published.')
    : mk('mtasts', 'MTA-STS', 5, 0, 'warn', 'No MTA-STS record.', 'Publish _mta-sts TXT and a policy file to enforce TLS for inbound mail.');
}

async function checkTls(mx) {
  if (!mx.length) return mk('tls', 'Mail server TLS', 10, 0, 'skip', 'No MX to test.');
  const host = mx[0].exchange;
  try {
    const r = await tlsService.inspect({ host, port: 25 });
    const crit = r.findings.filter((f) => f.severity === 'critical');
    const warn = r.findings.filter((f) => f.severity === 'warning');
    if (crit.length) return mk('tls', 'Mail server TLS', 10, 3, 'fail', `${host}: ${crit.map((f) => f.title).join(', ')}.`, 'Fix the certificate and use TLS 1.2 or newer.');
    if (warn.length) return mk('tls', 'Mail server TLS', 10, 7, 'warn', `${host}: ${warn.map((f) => f.title).join(', ')}.`, 'Install a publicly trusted certificate.');
    return mk('tls', 'Mail server TLS', 10, 10, 'pass', `${host}: ${r.connection.protocol}, trusted certificate.`);
  } catch (e) {
    if (e.code === 'NO_STARTTLS') return mk('tls', 'Mail server TLS', 10, 0, 'fail', `${host} does not offer STARTTLS.`, 'Enable STARTTLS on your MX.');
    return mk('tls', 'Mail server TLS', 10, 0, 'skip', `Could not test ${host}:25 (${e.message}).`);
  }
}

function grade(pct) {
  return pct >= 90 ? 'A' : pct >= 80 ? 'B' : pct >= 70 ? 'C' : pct >= 60 ? 'D' : 'F';
}

async function score(rawDomain, { selector } = {}) {
  const domain = String(rawDomain || '').trim().toLowerCase().replace(/^.*@/, '');
  if (!isValidHostname(domain)) throw Object.assign(new Error('Enter a valid domain name'), { code: 'BAD_INPUT' });
  if (selector && !/^[a-z0-9._-]{1,63}$/i.test(selector)) throw Object.assign(new Error('Invalid DKIM selector'), { code: 'BAD_INPUT' });

  const mx = await getMx(domain);
  const ips = await mxIps(mx);

  const checks = await Promise.all([
    checkMx(domain, mx), checkSpf(domain), checkDkim(domain, selector), checkDmarc(domain),
    checkRdns(ips), checkBlacklist(ips), checkMtaSts(domain), checkTls(mx),
  ]);

  const scored = checks.filter((c) => c.status !== 'skip');
  const max = scored.reduce((s, c) => s + c.max, 0) || 1;
  const pts = scored.reduce((s, c) => s + c.points, 0);
  const pct = Math.round((pts / max) * 100);
  const fixes = checks.filter((c) => c.fix && c.points < c.max).sort((a, b) => (b.max - b.points) - (a.max - a.points)).map((c) => ({ check: c.label, fix: c.fix }));

  return { domain, checkedAt: new Date().toISOString(), score: pct, grade: grade(pct), skipped: checks.filter((c) => c.status === 'skip').map((c) => c.label), checks, fixes };
}

module.exports = { score };
