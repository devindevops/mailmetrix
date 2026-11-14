'use strict';
// SSRF protection: only allow connections to public IPs.
// Single canonical blocklist: import isPrivateIp from here everywhere (tls, score, blacklist, smtp).
const dns = require('dns').promises;
const net = require('net');

const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;

function blocked(msg) {
  const e = new Error(msg);
  e.code = 'BLOCKED';
  return e;
}

// net.BlockList parses and normalises addresses itself, so non-canonical IPv6 spellings
// (0:0:0:0:0:ffff:7f00:1, ::127.0.0.1, ...) cannot slip past string-prefix checks.
//
// Two separate lists on purpose: Node matches IPv4 addresses against IPv6 rules as
// IPv4-mapped (::ffff:a.b.c.d), so a v6 rule like ::/8 would match every IPv4 address.
const BLOCK4 = new net.BlockList();
const BLOCK6 = new net.BlockList();
const v4 = (addr, prefix) => BLOCK4.addSubnet(addr, prefix, 'ipv4');
const v6 = (addr, prefix) => BLOCK6.addSubnet(addr, prefix, 'ipv6');

// --- IPv4 ---
v4('0.0.0.0', 8);          // "this" network
v4('10.0.0.0', 8);         // private
v4('100.64.0.0', 10);      // CGNAT
v4('127.0.0.0', 8);        // loopback
v4('169.254.0.0', 16);     // link-local / cloud metadata
v4('172.16.0.0', 12);      // private
v4('192.0.0.0', 24);       // IETF protocol assignments
v4('192.0.2.0', 24);       // TEST-NET-1
v4('192.88.99.0', 24);     // deprecated 6to4 relay anycast
v4('192.168.0.0', 16);     // private
v4('198.18.0.0', 15);      // benchmarking
v4('198.51.100.0', 24);    // TEST-NET-2
v4('203.0.113.0', 24);     // TEST-NET-3
v4('224.0.0.0', 4);        // multicast
v4('240.0.0.0', 4);        // reserved + broadcast

// --- IPv6 ---
v6('::', 8);               // unspecified, loopback, IPv4-compatible, IPv4-mapped (::ffff:0:0/96) and other reserved
v6('64:ff9b::', 96);       // NAT64 (embeds an IPv4 address)
v6('64:ff9b:1::', 48);     // local-use NAT64
v6('100::', 64);           // discard-only
v6('2001::', 23);          // IETF protocol assignments incl. Teredo (2001::/32), ORCHID, benchmarking
v6('2001:db8::', 32);      // documentation
v6('2002::', 16);          // 6to4 (embeds an IPv4 address)
v6('3fff::', 20);          // documentation (RFC 9637)
v6('5f00::', 16);          // SRv6 SIDs
v6('fc00::', 7);           // unique local
v6('fe80::', 10);          // link-local
v6('fec0::', 10);          // deprecated site-local
v6('ff00::', 8);           // multicast

// Returns true for anything that must not be contacted. Fails closed on garbage input.
function isPrivateIp(ip) {
  if (typeof ip !== 'string' || ip.includes('%')) return true; // also rejects zone IDs (fe80::1%eth0)
  try {
    if (net.isIPv4(ip)) return BLOCK4.check(ip, 'ipv4');
    if (net.isIPv6(ip)) return BLOCK6.check(ip, 'ipv6');
  } catch {
    return true;
  }
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

module.exports = { isPrivateIp, isBlockedIp: isPrivateIp, isValidHostname, resolvePublic, HOST_RE };