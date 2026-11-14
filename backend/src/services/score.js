'use strict';
// Deliverability score. Self-contained: swap the DNS helpers for your services/dns.js if you prefer.
//
// Abuse controls. The domain being scored is attacker-controlled, so are its SPF includes,
// MX targets and PTR names, which means they decide which third-party names/IPs get queried:
//  - per-request DNS query budget, SPF lookup cap (RFC 7208: 10), PTR-name cap and an overall deadline
//  - result cache per domain (with in-flight coalescing), plus caches keyed by the *target*
//    (MX IP for the port-25 probe, IP for DNSBL) so rotating attacker-owned domains cannot be
//    used to hammer one third-party host
//  - global hourly caps on outbound DNSBL lookups and port-25 probes, and a concurrency cap
const dns = require('dns');
const { isValidHostname, isPrivateIp } = require('./netguard');
const blacklist = require('./blacklist');
const tlsService = require('./tls');

const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'mail', 'dkim', 'smtp', 'mandrill', 'mailjet', 'amazonses', 'zoho', 'sendgrid', 'em', 'protonmail'];

const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);
const CACHE_TTL_MS = num(process.env.SCORE_CACHE_TTL_SECONDS, 300) * 1000;     // per-domain result cache
const CACHE_MAX = num(process.env.SCORE_CACHE_MAX, 500);
const TARGET_TTL_MS = num(process.env.SCORE_TARGET_TTL_SECONDS, 900) * 1000;   // per MX IP / DNSBL IP
const MAX_DNS_QUERIES = num(process.env.SCORE_MAX_DNS_QUERIES, 80);            // per request (normal use is ~55 max)
const DEADLINE_MS = num(process.env.SCORE_DEADLINE_SECONDS, 25) * 1000;        // per request
const MAX_CONCURRENT = num(process.env.SCORE_MAX_CONCURRENT, 8);               // simultaneous uncached runs
const SPF_LIMIT = 10;                                                          // RFC 7208 section 4.6.4
const MAX_PTR_NAMES = 2;

const fail = (msg, code) => Object.assign(new Error(msg), { code });

// Cache of promises: concurrent identical requests share one run, failures are never cached.
function ttlCache(ttlMs, max) {
  const m = new Map();
  return {
    has: (key) => { const e = m.get(key); return Boolean(e && e.exp > Date.now()); },
    get(key, loader) {
      const e = m.get(key);
      if (e && e.exp > Date.now()) return e.p;
      const p = Promise.resolve().then(loader);
      m.delete(key);
      m.set(key, { p, exp: Date.now() + ttlMs });
      if (m.size > max) m.delete(m.keys().next().value); // bound memory: drop the oldest entry
      p.catch(() => { if (m.get(key)?.p === p) m.delete(key); });
      return p;
    },
  };
}

// Fixed-window global cap for outbound traffic to third parties.
function makeWindow(limit, ms) {
  let start = Date.now();
  let count = 0;
  return {
    take() {
      const now = Date.now();
      if (now - start >= ms) { start = now; count = 0; }
      if (count >= limit) return false;
      count += 1;
      return true;
    },
  };
}

const scoreCache = ttlCache(CACHE_TTL_MS, CACHE_MAX);
const tlsCache = ttlCache(TARGET_TTL_MS, 1000);
const dnsblCache = ttlCache(TARGET_TTL_MS, 2000);
const dnsblWindow = makeWindow(num(process.env.SCORE_DNSBL_IPS_PER_HOUR, 300), 3600000);
const tlsWindow = makeWindow(num(process.env.SCORE_TLS_PROBES_PER_HOUR, 120), 3600000);
let active = 0;

// Per-request DNS helper: memoised (no duplicate queries), budgeted and deadline-bound.
function makeDns() {
  const st = { queries: 0, exhausted: false, deadline: Date.now() + DEADLINE_MS };
  const memo = new Map();
  const q = (key, fn) => {
    if (memo.has(key)) return memo.get(key);
    if (st.queries >= MAX_DNS_QUERIES || Date.now() > st.deadline) {
      st.exhausted = true;
      return Promise.reject(fail('DNS budget exceeded', 'TOO_COMPLEX'));
    }
    st.queries += 1;
    const p = Promise.resolve().then(fn);
    memo.set(key, p);
    return p;
  };
  return {
    st,
    txt: async (name) => {
      try { return (await q(`txt:${name}`, () => resolver.resolveTxt(name))).map((c) => c.join('')); } catch { return []; }
    },
    mx: (name) => q(`mx:${name}`, () => resolver.resolveMx(name)),
    a: (name) => q(`a:${name}`, () => resolver.resolve4(name)),
    ptr: (ip) => q(`ptr:${ip}`, () => resolver.reverse(ip)),
  };
}

const safe = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };

const mk = (id, label, max, points, status, detail, fix) => ({ id, label, max, points: Math.round(points * 10) / 10, status, detail, fix: fix || null });

async function getMx(d, domain) {
  const mx = await safe(() => d.mx(domain), []);
  return mx.filter((m) => m.exchange && m.exchange !== '.').sort((a, b) => a.priority - b.priority);
}

// Only public FQDNs are resolved, and private addresses are dropped, so internal DNS names
// (Docker service names, corp hosts) can never be probed or leaked through the report.
async function mxIps(d, mx) {
  const out = [];
  for (const m of mx.slice(0, 3)) {
    if (!isValidHostname(m.exchange)) continue;
    const ips = await safe(() => d.a(m.exchange), []);
    for (const ip of ips.slice(0, 2)) if (!isPrivateIp(ip)) out.push({ host: m.exchange, ip });
  }
  return out;
}

// RFC 7208 allows 10 DNS-querying terms. Stop querying as soon as the limit is passed:
// the "depth" limit alone does not bound breadth (a record can contain hundreds of includes).
async function spfLookups(d, domain, st = { n: 0, seen: new Set() }, depth = 0) {
  if (depth > SPF_LIMIT || st.seen.has(domain)) return st.n;
  st.seen.add(domain);
  const rec = (await d.txt(domain)).find((t) => /^v=spf1\b/i.test(t));
  if (!rec) return st.n;
  for (const term of rec.split(/\s+/).slice(1)) {
    if (st.n > SPF_LIMIT) return st.n;
    const m = term.replace(/^[+\-~?]/, '');
    const isInclude = /^include:/i.test(m);
    const isRedirect = /^redirect=/i.test(m);
    if (isInclude || isRedirect) {
      st.n += 1;
      if (st.n > SPF_LIMIT) return st.n;
      const target = m.slice(isInclude ? 8 : 9).toLowerCase();
      if (isValidHostname(target)) await spfLookups(d, target, st, depth + 1); // skips macros / junk names
    } else if (/^(a|mx)(:|\/|$)/i.test(m) || /^(ptr|exists:)/i.test(m)) {
      st.n += 1;
    }
  }
  return st.n;
}

async function checkMx(domain, mx) {
  if (!mx.length) return mk('mx', 'MX records', 10, 0, 'fail', 'No MX records found.', 'Add MX records pointing at your mail servers.');
  if (mx.length === 1) return mk('mx', 'MX records', 10, 8, 'warn', `1 MX record (${mx[0].exchange}).`, 'Add a secondary MX for redundancy.');
  return mk('mx', 'MX records', 10, 10, 'pass', `${mx.length} MX records, primary ${mx[0].exchange}.`);
}

async function checkSpf(d, domain) {
  const recs = (await d.txt(domain)).filter((t) => /^v=spf1\b/i.test(t));
  if (!recs.length) return mk('spf', 'SPF', 20, 0, 'fail', 'No SPF record found.', 'Publish a TXT record such as "v=spf1 include:<provider> -all".');
  if (recs.length > 1) return mk('spf', 'SPF', 20, 4, 'fail', `${recs.length} SPF records found; receivers will return PermError.`, 'Merge into a single SPF record.');
  const rec = recs[0];
  const lookups = await spfLookups(d, domain);
  let pts = 20;
  const notes = [];
  let status = 'pass';
  let fix = null;
  if (/\s\+all\b/i.test(rec) || /\sall\b/i.test(rec) && !/[-~?]all/i.test(rec)) { pts = 2; status = 'fail'; notes.push('Allows any sender (+all).'); fix = 'Replace with -all or ~all.'; }
  else if (/\s\?all\b/i.test(rec)) { pts -= 10; status = 'warn'; notes.push('Neutral policy (?all).'); fix = 'Use ~all or -all.'; }
  else if (/\s~all\b/i.test(rec)) { pts -= 3; notes.push('Soft fail (~all).'); }
  else if (/\s-all\b/i.test(rec)) notes.push('Hard fail (-all).');
  else if (!/redirect=/i.test(rec)) { pts -= 8; status = 'warn'; notes.push('No "all" mechanism.'); fix = 'End the record with -all or ~all.'; }
  if (lookups > SPF_LIMIT) { pts = Math.min(pts, 6); status = 'fail'; notes.push(`Over ${SPF_LIMIT} DNS lookups (limit is ${SPF_LIMIT}).`); fix = 'Flatten includes to stay at 10 lookups or fewer.'; }
  else if (lookups >= 8) { pts -= 2; if (status === 'pass') status = 'warn'; notes.push(`${lookups}/10 DNS lookups.`); }
  else notes.push(`${lookups}/10 DNS lookups.`);
  return mk('spf', 'SPF', 20, Math.max(pts, 0), status, notes.join(' '), fix);
}

async function checkDkim(d, domain, selector) {
  const selectors = selector ? [selector] : DKIM_SELECTORS;
  const found = [];
  await Promise.all(selectors.map(async (s) => {
    const r = await d.txt(`${s}._domainkey.${domain}`);
    if (r.some((t) => /v=DKIM1|p=/i.test(t))) found.push(s);
  }));
  if (found.length) return mk('dkim', 'DKIM', 15, 15, 'pass', `Key found for selector(s): ${found.join(', ')}.`);
  return selector
    ? mk('dkim', 'DKIM', 15, 0, 'fail', `No DKIM key at ${selector}._domainkey.${domain}.`, 'Publish your DKIM public key or check the selector name.')
    : mk('dkim', 'DKIM', 15, 7, 'warn', 'No key found on common selectors (yours may use a custom one).', 'Re-run with your DKIM selector to verify.');
}

async function checkDmarc(d, domain) {
  const rec = (await d.txt(`_dmarc.${domain}`)).find((t) => /^v=DMARC1/i.test(t));
  if (!rec) return mk('dmarc', 'DMARC', 20, 0, 'fail', 'No DMARC record found.', 'Add _dmarc TXT: "v=DMARC1; p=none; rua=mailto:dmarc@' + domain + '".');
  const p = (rec.match(/\bp=(\w+)/i) || [])[1]?.toLowerCase();
  const hasRua = /\brua=/i.test(rec);
  let pts = { reject: 20, quarantine: 17, none: 9 }[p] ?? 5;
  if (!hasRua) pts -= 2;
  const status = p === 'reject' || p === 'quarantine' ? 'pass' : 'warn';
  const fix = p === 'none' ? 'Move to p=quarantine, then p=reject once reports look clean.' : !hasRua ? 'Add an rua= address to receive aggregate reports.' : null;
  return mk('dmarc', 'DMARC', 20, Math.max(pts, 0), status, `Policy p=${p || 'unknown'}${hasRua ? ', reporting enabled' : ', no reporting address'}.`, fix);
}

async function checkRdns(d, ips) {
  if (!ips.length) return mk('rdns', 'Reverse DNS (FCrDNS)', 10, 0, 'skip', 'No MX IPs to test.');
  const good = await Promise.all(ips.map(async ({ ip }) => {
    // An attacker controls PTR answers for their own IP space: cap how many names we chase.
    const names = (await safe(() => d.ptr(ip), [])).slice(0, MAX_PTR_NAMES);
    for (const n of names) {
      if (!isValidHostname(n)) continue;
      const fwd = await safe(() => d.a(n), []);
      if (fwd.includes(ip)) return true;
    }
    return false;
  }));
  const ok = good.filter(Boolean).length;
  const bad = ips.filter((_, i) => !good[i]).map((x) => x.ip);
  const pts = (ok / ips.length) * 10;
  if (!bad.length) return mk('rdns', 'Reverse DNS (FCrDNS)', 10, 10, 'pass', `All ${ips.length} MX IP(s) have matching PTR and A records.`);
  return mk('rdns', 'Reverse DNS (FCrDNS)', 10, pts, ok ? 'warn' : 'fail', `No forward-confirmed PTR for: ${bad.join(', ')}.`, 'Ask your host to set a PTR that resolves back to the same IP.');
}

async function checkBlacklist(ips) {
  if (!ips.length) return mk('blacklist', 'Blacklists', 10, 0, 'skip', 'No MX IPs to test.');
  const unique = [...new Set(ips.map((i) => i.ip))].slice(0, 3);
  // Cached per IP, so many domains pointing at one IP cannot repeatedly hit the DNSBL operators.
  const results = await Promise.all(unique.map((ip) => safe(() => dnsblCache.get(ip, () => {
    if (!dnsblWindow.take()) throw fail('DNSBL checks limited', 'LIMITED');
    return blacklist.checkIp(ip);
  }), null)));
  const flat = results.filter(Boolean).flatMap((r) => r.results.filter((x) => x.status === 'listed').map((x) => `${r.target} on ${x.name}`));
  const known = results.filter(Boolean).flatMap((r) => r.results).filter((x) => x.status !== 'unknown').length;
  if (!known) return mk('blacklist', 'Blacklists', 10, 0, 'skip', 'Blacklist servers did not answer, or checks are temporarily limited.');
  if (!flat.length) return mk('blacklist', 'Blacklists', 10, 10, 'pass', `MX IPs are clean on ${known} lookups.`);
  return mk('blacklist', 'Blacklists', 10, Math.max(0, 10 - flat.length * 5), 'fail', `Listed: ${flat.join('; ')}.`, 'Request delisting and fix the cause (compromised account, open relay, bad reputation).');
}

async function checkMtaSts(d, domain) {
  const rec = (await d.txt(`_mta-sts.${domain}`)).find((t) => /^v=STSv1/i.test(t));
  return rec
    ? mk('mtasts', 'MTA-STS', 5, 5, 'pass', 'MTA-STS record published.')
    : mk('mtasts', 'MTA-STS', 5, 0, 'warn', 'No MTA-STS record.', 'Publish _mta-sts TXT and a policy file to enforce TLS for inbound mail.');
}

async function probeTls(host) {
  if (!tlsWindow.take()) throw fail('TLS probes limited', 'LIMITED');
  try {
    const r = await tlsService.inspect({ host, port: 25 });
    const crit = r.findings.filter((f) => f.severity === 'critical');
    const warn = r.findings.filter((f) => f.severity === 'warning');
    if (crit.length) return mk('tls', 'Mail server TLS', 10, 3, 'fail', `${host}: ${crit.map((f) => f.title).join(', ')}.`, 'Fix the certificate and use TLS 1.2 or newer.');
    if (warn.length) return mk('tls', 'Mail server TLS', 10, 7, 'warn', `${host}: ${warn.map((f) => f.title).join(', ')}.`, 'Install a publicly trusted certificate.');
    return mk('tls', 'Mail server TLS', 10, 10, 'pass', `${host}: ${r.connection.protocol}, trusted certificate.`);
  } catch (e) {
    if (e.code === 'NO_STARTTLS') return mk('tls', 'Mail server TLS', 10, 0, 'fail', `${host} does not offer STARTTLS.`, 'Enable STARTTLS on your MX.');
    // Deliberately generic: error text would reveal whether internal names exist or which ports are open.
    return mk('tls', 'Mail server TLS', 10, 0, 'skip', `Could not test ${host}:25.`);
  }
}

async function checkTls(mx, ips) {
  if (!mx.length) return mk('tls', 'Mail server TLS', 10, 0, 'skip', 'No MX to test.');
  const host = mx[0].exchange;
  if (!isValidHostname(host)) return mk('tls', 'Mail server TLS', 10, 0, 'skip', 'Primary MX is not a public hostname.');
  // Key by the target IP when known: attacker-owned hostnames pointing at one victim share a cache entry.
  const target = ips.find((i) => i.host === host)?.ip || host.toLowerCase();
  try {
    return await tlsCache.get(target, () => probeTls(host));
  } catch {
    return mk('tls', 'Mail server TLS', 10, 0, 'skip', 'TLS checks are temporarily limited; try again later.');
  }
}

function grade(pct) {
  return pct >= 90 ? 'A' : pct >= 80 ? 'B' : pct >= 70 ? 'C' : pct >= 60 ? 'D' : 'F';
}

async function run(domain, selector) {
  if (active >= MAX_CONCURRENT) throw fail('Scoring is busy, try again shortly', 'BUSY');
  active += 1;
  try {
    const d = makeDns();
    const mx = await getMx(d, domain);
    const ips = await mxIps(d, mx);

    const checks = await Promise.all([
      checkMx(domain, mx), checkSpf(d, domain), checkDkim(d, domain, selector), checkDmarc(d, domain),
      checkRdns(d, ips), checkBlacklist(ips), checkMtaSts(d, domain), checkTls(mx, ips),
    ]);

    // Budget or deadline hit: some checks saw "no records" only because we stopped asking.
    if (d.st.exhausted) throw fail('This domain needs too many DNS lookups to analyze', 'TOO_COMPLEX');

    const scored = checks.filter((c) => c.status !== 'skip');
    const max = scored.reduce((s, c) => s + c.max, 0) || 1;
    const pts = scored.reduce((s, c) => s + c.points, 0);
    const pct = Math.round((pts / max) * 100);
    const fixes = checks.filter((c) => c.fix && c.points < c.max).sort((a, b) => (b.max - b.points) - (a.max - a.points)).map((c) => ({ check: c.label, fix: c.fix }));

    return { domain, checkedAt: new Date().toISOString(), score: pct, grade: grade(pct), skipped: checks.filter((c) => c.status === 'skip').map((c) => c.label), checks, fixes };
  } finally {
    active -= 1;
  }
}

async function score(rawDomain, { selector } = {}) {
  const domain = String(rawDomain || '').trim().toLowerCase().replace(/^.*@/, '');
  if (!isValidHostname(domain)) throw Object.assign(new Error('Enter a valid domain name'), { code: 'BAD_INPUT' });
  if (selector && !/^[a-z0-9._-]{1,63}$/i.test(selector)) throw Object.assign(new Error('Invalid DKIM selector'), { code: 'BAD_INPUT' });

  const key = `${domain}|${selector ? selector.toLowerCase() : ''}`;
  const cached = scoreCache.has(key);
  const result = await scoreCache.get(key, () => run(domain, selector));
  return cached ? { ...result, cached: true } : result;
}

module.exports = { score };