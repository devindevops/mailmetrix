'use strict';
// File-backed share store with TTL. Mount DATA_DIR as a Docker volume to persist.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = process.env.SHARE_DIR || path.join(__dirname, '..', '..', 'data', 'shares');
const TTL_MS = (Number(process.env.SHARE_TTL_DAYS) || 7) * 86400000;
const MAX_BYTES = 256 * 1024;
const MAX_FILES = 5000;
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

function create(type, data) {
  if (!TYPES.has(type)) throw fail('Unknown result type', 'BAD_INPUT');
  if (!data || typeof data !== 'object') throw fail('Result data must be an object', 'BAD_INPUT');
  const body = JSON.stringify({ type, data: sanitize(data), createdAt: Date.now(), expiresAt: Date.now() + TTL_MS });
  if (Buffer.byteLength(body) > MAX_BYTES) throw fail('Result too large to share', 'TOO_LARGE');
  if (fs.readdirSync(DIR).length >= MAX_FILES) throw fail('Share storage is full, try again later', 'FULL');
  const id = crypto.randomBytes(9).toString('base64url');
  fs.writeFileSync(file(id), body, { mode: 0o600 });
  return { id, expiresAt: new Date(Date.now() + TTL_MS).toISOString() };
}

function get(id) {
  if (!ID_RE.test(id)) return null;
  let raw;
  try { raw = fs.readFileSync(file(id), 'utf8'); } catch { return null; }
  const rec = JSON.parse(raw);
  if (rec.expiresAt < Date.now()) { fs.rm(file(id), () => {}); return null; }
  return rec;
}

function cleanup() {
  for (const f of fs.readdirSync(DIR)) {
    try {
      const rec = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
      if (rec.expiresAt < Date.now()) fs.rmSync(path.join(DIR, f));
    } catch { fs.rmSync(path.join(DIR, f), { force: true }); }
  }
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