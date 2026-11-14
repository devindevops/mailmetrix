'use strict';

// Central SSRF protection.
// All services making outbound connections should use resolvePublic()
// and isPrivateIp() from this module.

const dns = require('dns').promises;
const net = require('net');

const HOST_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function blocked(msg) {
  const error = new Error(msg);
  error.code = 'BLOCKED';
  return error;
}

// Separate IPv4 and IPv6 blocklists.
// Node's BlockList handles canonical address normalization,
// including IPv4-mapped IPv6 addresses.

const BLOCK4 = new net.BlockList();
const BLOCK6 = new net.BlockList();

const v4 = (address, prefix) =>
  BLOCK4.addSubnet(address, prefix, 'ipv4');

const v6 = (address, prefix) =>
  BLOCK6.addSubnet(address, prefix, 'ipv6');

// --------------------------------------------------
// IPv4 blocked ranges
// --------------------------------------------------

v4('0.0.0.0', 8);          // Current network
v4('10.0.0.0', 8);         // Private
v4('100.64.0.0', 10);      // Carrier-grade NAT
v4('127.0.0.0', 8);        // Loopback
v4('169.254.0.0', 16);     // Link-local / cloud metadata
v4('172.16.0.0', 12);      // Private
v4('192.0.0.0', 24);       // IETF protocol assignments
v4('192.0.2.0', 24);       // TEST-NET-1
v4('192.88.99.0', 24);     // Deprecated 6to4 relay
v4('192.168.0.0', 16);     // Private
v4('198.18.0.0', 15);      // Benchmarking
v4('198.51.100.0', 24);    // TEST-NET-2
v4('203.0.113.0', 24);     // TEST-NET-3
v4('224.0.0.0', 4);        // Multicast
v4('240.0.0.0', 4);        // Reserved / broadcast

// --------------------------------------------------
// IPv6 blocked ranges
// --------------------------------------------------

v6('::', 8);               // Unspecified, loopback, mapped and compatible
v6('64:ff9b::', 96);       // Well-known NAT64
v6('64:ff9b:1::', 48);     // Local-use NAT64
v6('100::', 64);           // Discard-only
v6('2001::', 23);          // IETF protocol assignments / Teredo / ORCHID
v6('2001:db8::', 32);      // Documentation
v6('2002::', 16);          // 6to4
v6('3fff::', 20);          // Documentation
v6('5f00::', 16);          // SRv6 SIDs
v6('fc00::', 7);           // Unique local
v6('fe80::', 10);          // Link-local
v6('fec0::', 10);          // Deprecated site-local
v6('ff00::', 8);           // Multicast

// --------------------------------------------------
// IP validation
// --------------------------------------------------

function isPrivateIp(ip) {
  if (typeof ip !== 'string' || ip.includes('%')) {
    return true;
  }

  try {
    if (net.isIPv4(ip)) {
      return BLOCK4.check(ip, 'ipv4');
    }

    if (net.isIPv6(ip)) {
      return BLOCK6.check(ip, 'ipv6');
    }
  } catch {
    return true;
  }

  // Fail closed for invalid or unsupported addresses.
  return true;
}

// --------------------------------------------------
// Hostname validation
// --------------------------------------------------

function isValidHostname(host) {
  return (
    typeof host === 'string' &&
    host.length <= 253 &&
    HOST_RE.test(host)
  );
}

// --------------------------------------------------
// Public DNS resolution
// --------------------------------------------------

async function resolvePublic(host) {
  if (typeof host !== 'string') {
    throw blocked('Invalid hostname');
  }

  host = host.trim().toLowerCase();

  if (!host || host.length > 253) {
    throw blocked('Invalid hostname');
  }

  // Handle IP addresses directly.
  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      throw blocked(
        'Private or reserved IP addresses are not allowed'
      );
    }

    return [host];
  }

  // Reject URLs, ports, paths, credentials and malformed hostnames.
  if (!isValidHostname(host)) {
    throw blocked('Invalid hostname');
  }

  let addresses;

  try {
    addresses = await dns.lookup(host, {
      all: true,
      verbatim: true,
    });
  } catch {
    const error = new Error(`Could not resolve ${host}`);
    error.code = 'ENOTFOUND';
    throw error;
  }

  if (!Array.isArray(addresses) || addresses.length === 0) {
    const error = new Error(`No addresses for ${host}`);
    error.code = 'ENOTFOUND';
    throw error;
  }

  // Reject the entire hostname if ANY address is unsafe.
  // Do not simply filter private addresses out of the results.

  for (const entry of addresses) {
    if (
      !entry ||
      typeof entry.address !== 'string' ||
      isPrivateIp(entry.address)
    ) {
      throw blocked(
        'Host resolves to a private or reserved address'
      );
    }
  }

  // Remove duplicate addresses.
  return [
    ...new Set(addresses.map(({ address }) => address)),
  ];
}

module.exports = {
  isPrivateIp,
  isBlockedIp: isPrivateIp,
  isValidHostname,
  resolvePublic,
  HOST_RE,
};