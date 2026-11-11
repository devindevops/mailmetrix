'use strict';
// Maps service errors to HTTP responses.
const CLIENT = new Set(['BAD_INPUT', 'BLOCKED', 'ENOTFOUND']);
module.exports = function sendError(res, e) {
  if (CLIENT.has(e.code)) return res.status(400).json({ error: e.message });
  if (e.code === 'TOO_LARGE') return res.status(413).json({ error: e.message });
  if (e.code === 'FULL') return res.status(507).json({ error: e.message });
  if (['TIMEOUT', 'ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'NO_STARTTLS', 'STARTTLS_REJECTED', 'BAD_GREETING', 'NO_CERT'].includes(e.code)) {
    return res.status(502).json({ error: e.message });
  }
  console.error(e);
  return res.status(500).json({ error: 'Internal error' });
};
