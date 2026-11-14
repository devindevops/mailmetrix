'use strict';
// File-backed share store with TTL, per-IP quota and oldest-first eviction.
// Mount DATA_DIR as a Docker volume to persist.
// NOTE: the in-memory index and quota assume a single Node process (no cluster / multiple replicas).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');

const DIR = process.env.SHARE_DIR || path.join(__dirname, '..', '..', 'data', 'shares');
const TTL_MS = (Number(process.env.SHARE_TTL_DAYS) || 2) * 86400000;
const MAX_BYTES = 256 * 1024;
const MAX_FILES = Number(process.env.SHARE_MAX_FILES) || 5000;
const MAX_TOTAL_BYTES = (Number(process.env.SHARE_MAX_TOTAL_MB) || 512) * 1024 * 1024;
const PER_IP_DAILY = Number(process.env.SHARE_PER_IP_DAILY) || 30;
const MAX_TRACKED_IPS = 100000;
// Header shares contain only the parsed analysis (the client never sends raw header text).
const TYPES = new Set(['blacklist', 'score', 'tls', 'smtp', 'dns', 'generator', 'headers']);

// Defence in depth: whatever the client sends, private keys and secrets are removed before storage.
const PEM_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
const SECRET_KEY_RE = /(priv(ate)?[_-]?key|passw(or)?d|secret|token|api[_-]?key)/i;

function sanitize(value, depth = 0) {
  if (depth > 12) return undefined;
  if (typeof value === 'string') return value.replace(PEM_RE, '[private key removed]');
  if (Array.isArray(value)) return value.map((v) => sanitize(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY_RE.test(k) ? '[removed]' : sanitize(v, depth + 1);
    }
    return out;
  }
  return value;
}
const ID_RE = /^[A-Za-z0-9_-]{8,16}$/;

fs.mkdirSync(DIR, { recursive: true });

const fail = (msg, code) => Object.assign(new Error(msg), { code });
const file = (id) => path.join(DIR, `${id}.json`);

// --- in-memory index (avoids scanning the directory on every create) ---
// id -> { exp, size }. A Map iterates in insertion order, so the first key is the oldest share.
const index = new Map();
let totalBytes = 0;

(function initIndex() {
  const entries = [];
  for (const f of fs.readdirSync(DIR)) {
    if (!f.endsWith('.json')) continue;
    const id = f.slice(0, -5);
    if (!ID_RE.test(id)) continue;
    try {
      const st = fs.statSync(path.join(DIR, f));
      entries.push({ id, size: st.size, exp: st.mtimeMs + TTL_MS, t: st.mtimeMs });
    } catch { /* file vanished, ignore */ }
  }
  entries.sort((a, b) => a.t - b.t);
  for (const { id, size, exp } of entries) {
    index.set(id, { exp, size });
    totalBytes += size;
  }
})();

function removeShare(id) {
  fs.promises.rm(file(id), { force: true }).catch(() => {});
  const meta = index.get(id);
  if (meta) {
    totalBytes -= meta.size;
    index.delete(id);
  }
}

// --- per-IP daily quota ---
const hits = new Map(); // ip -> { count, resetAt }

// Quota key for a client. Fails loudly when the route forgot to pass req.ip: silently falling back
// to a shared bucket would make every client share one quota. IPv6 clients are keyed by /64, since
// one subscriber normally controls a whole /64 and could otherwise rotate addresses to dodge the limit.
function clientKey(ip) {
  const s = typeof ip === 'string' ? ip.trim().toLowerCase() : '';
  if (!s || !net.isIP(s)) throw fail('Client IP missing or invalid (pass req.ip to create())', 'NO_CLIENT_IP');
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/); // IPv4-mapped IPv6 -> plain IPv4
  if (mapped) return mapped[1];
  if (net.isIPv4(s)) return s;
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = s.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h;
  return `${groups.slice(0, 4).map((g) => g.padStart(4, '0')).join(':')}::/64`;
}

function allow(key) {
  const now = Date.now();
  let h = hits.get(key);
  if (!h || h.resetAt < now) {
    if (!hits.has(key) && hits.size >= MAX_TRACKED_IPS) {
      hits.delete(hits.keys().next().value); // bound memory under IP-spoofing floods
    }
    h = { count: 0, resetAt: now + 86400000 };
  }
  if (h.count >= PER_IP_DAILY) return false;
  h.count++;
  hits.set(key, h);
  return true;
}

async function create(type, data, ip) {
  const key = clientKey(ip); // throws NO_CLIENT_IP (-> 500 + log) if the route did not pass req.ip
  if (!TYPES.has(type)) throw fail('Unknown result type', 'BAD_INPUT');
  if (!data || typeof data !== 'object') throw fail('Result data must be an object', 'BAD_INPUT');
  if (!allow(key)) throw fail('Daily share limit reached for this client', 'RATE_LIMITED'); // map to HTTP 429

  const now = Date.now();
  const body = JSON.stringify({ type, data: sanitize(data), createdAt: now, expiresAt: now + TTL_MS });
  const size = Buffer.byteLength(body);
  if (size > MAX_BYTES) throw fail('Result too large to share', 'TOO_LARGE');

  // Fallback only: the per-IP quota makes it hard for a single client to trigger eviction.
  // Drops the oldest shares (first-in, first-out) instead of refusing new ones.
  while (index.size > 0 && (index.size >= MAX_FILES || totalBytes + size > MAX_TOTAL_BYTES)) {
    removeShare(index.keys().next().value);
  }

  const id = crypto.randomBytes(9).toString('base64url');
  const tmp = path.join(DIR, `${id}.tmp`); // not *.json, so it is never served or indexed half-written
  await fs.promises.writeFile(tmp, body, { mode: 0o600 });
  await fs.promises.rename(tmp, file(id));
  index.set(id, { exp: now + TTL_MS, size });
  totalBytes += size;
  return { id, expiresAt: new Date(now + TTL_MS).toISOString() };
}

async function get(id) {
  if (!ID_RE.test(id)) return null;
  let rec;
  try {
    rec = JSON.parse(await fs.promises.readFile(file(id), 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') removeShare(id); // corrupt file: drop it
    else if (index.has(id)) removeShare(id);  // index drifted from disk
    return null;
  }
  const meta = index.get(id);
  if (rec.expiresAt < Date.now() || (meta && meta.exp < Date.now())) {
    removeShare(id);
    return null;
  }
  return rec;
}

async function cleanup() {
  const now = Date.now();
  for (const [id, meta] of index) {
    if (meta.exp < now) removeShare(id);
  }
  // remove stray temp files left by a crash mid-write
  try {
    const files = await fs.promises.readdir(DIR);
    for (const f of files) {
      if (f.endsWith('.tmp')) await fs.promises.rm(path.join(DIR, f), { force: true });
    }
  } catch { /* ignore */ }
  for (const [ip, h] of hits) if (h.resetAt < now) hits.delete(ip);
}
setInterval(cleanup, 3600000).unref();

// --- export helpers ---
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function flatten(obj, prefix = '', out = []) {
  if (Array.isArray(obj)) obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
  else if (obj && typeof obj === 'object') Object.entries(obj).forEach(([k, v]) => flatten(v, prefix ? `${prefix}.${k}` : k, out));
  else out.push([prefix, obj ?? '']);
  return out;
}

function toCsv(data) {
  const cell = (v) => {
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // CSV injection guard
    return `"${s.replace(/"/g, '""')}"`;
  };
  return ['field,value', ...flatten(data).map(([k, v]) => `${cell(k)},${cell(v)}`)].join('\r\n');
}

function toHtml(rec, id) {
  const rows = flatten(rec.data).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MailProbe ${esc(rec.type)} report</title>
<style>body{font:14px system-ui,sans-serif;margin:2rem auto;max-width:900px;padding:0 1rem}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top;word-break:break-word}th{width:35%;background:#f4f4f4}</style></head>
<body><h1>MailProbe ${esc(rec.type)} report</h1><p>ID ${esc(id)} &middot; created ${esc(new Date(rec.createdAt).toISOString())}</p><table>${rows}</table></body></html>`;
}

module.exports = { create, get, toCsv, toHtml };