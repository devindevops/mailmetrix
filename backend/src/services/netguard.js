'use strict';
// SSRF protection: only allow connections to public IPs.
const dns = require('dns').promises;
const net = require('net');

const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;

function blocked(msg) {
  const e = new Error(msg);
  e.code = 'BLOCKED';
  return e;
}

function isPrivateIPv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

function isPrivateIPv6(ip) {
  const l = ip.toLowerCase();
  if (l === '::' || l === '::1') return true;
  if (l.startsWith('::ffff:')) {
    const v4 = l.slice(7);
    return net.isIPv4(v4) ? isPrivateIPv4(v4) : true;
  }
  return /^(fc|fd|fe[89ab])/.test(l);
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true;
}

function isValidHostname(h) {
  return typeof h === 'string' && HOST_RE.test(h);
}

// Resolve a host and return public IPs only. Throws BLOCKED otherwise.
// Connect to the returned IP (not the hostname) to avoid DNS rebinding.
async function resolvePublic(host) {
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw blocked('Private or reserved IP addresses are not allowed');
    return [host];
  }
  if (!isValidHostname(host)) throw blocked('Invalid hostname');
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    const e = new Error(`Could not resolve ${host}`);
    e.code = 'ENOTFOUND';
    throw e;
  }
  if (!addrs.length) throw new Error(`No addresses for ${host}`);
  if (addrs.some((a) => isPrivateIp(a.address))) throw blocked('Host resolves to a private or reserved address');
  return addrs.map((a) => a.address);
}

module.exports = { isPrivateIp, isValidHostname, resolvePublic, HOST_RE };
