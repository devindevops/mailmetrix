'use strict';

// Central SSRF protection.
//
// All services making outbound connections must use resolvePublic()
// and isPrivateIp() from this module.
//
// Security policy:
// - Reject private, loopback, link-local and reserved addresses.
// - Reject non-global IPv4 and IPv6 destinations.
// - Reject hostnames resolving to even one prohibited address.
// - Connect using validated IP addresses, not the original hostname.
//
// IP ranges below are intentional security constants.
// They are NOT outbound connection destinations.

const dns = require('dns').promises;
const net = require('net');

// --------------------------------------------------
// Hostname validation
// --------------------------------------------------

const HOST_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const BLOCKED_DOMAINS_RE =
  /\.(localhost|local|internal|arpa|invalid|test|example)$/i;

// --------------------------------------------------
// Error handling
// --------------------------------------------------

function blocked(message) {
  const error = new Error(message);
  error.code = 'BLOCKED';
  return error;
}

// --------------------------------------------------
// IPv4 blocked ranges
// --------------------------------------------------

// These ranges include private, loopback, link-local,
// shared-address, documentation, benchmarking,
// multicast and reserved address spaces.
//
// Maintain against the IANA IPv4 Special-Purpose
// Address Registry.

const BLOCKED_IPV4_RANGES = Object.freeze([
  ['0.0.0.0', 8],          // Current network
  ['10.0.0.0', 8],         // Private
  ['100.64.0.0', 10],      // Carrier-grade NAT
  ['127.0.0.0', 8],        // Loopback
  ['169.254.0.0', 16],     // Link-local / metadata
  ['172.16.0.0', 12],      // Private
  ['192.0.0.0', 24],       // IETF protocol assignments
  ['192.0.2.0', 24],       // TEST-NET-1
  ['192.88.99.0', 24],     // Deprecated 6to4 relay
  ['192.168.0.0', 16],     // Private
  ['198.18.0.0', 15],      // Benchmarking
  ['198.51.100.0', 24],    // TEST-NET-2
  ['203.0.113.0', 24],     // TEST-NET-3
  ['224.0.0.0', 4],        // Multicast
  ['240.0.0.0', 4],        // Reserved / broadcast
]);

// --------------------------------------------------
// IPv6 blocked ranges
// --------------------------------------------------

// IPv6 ranges include unspecified, loopback, mapped,
// translation, documentation, unique-local,
// link-local, multicast and special-purpose ranges.
//
// IPv4-mapped IPv6 addresses are handled separately
// through explicit IPv4 extraction and validation.

const BLOCKED_IPV6_RANGES = Object.freeze([
  ['::', 8],               // Unspecified / loopback / mapped
  ['64:ff9b::', 96],       // Well-known NAT64
  ['64:ff9b:1::', 48],     // Local-use NAT64
  ['100::', 64],           // Discard-only
  ['2001::', 23],          // IETF special-purpose assignments
  ['2001:db8::', 32],      // Documentation
  ['2002::', 16],          // 6to4
  ['3fff::', 20],          // Documentation
  ['5f00::', 16],          // SRv6 SIDs
  ['fc00::', 7],           // Unique-local
  ['fe80::', 10],          // Link-local
  ['fec0::', 10],          // Deprecated site-local
  ['ff00::', 8],           // Multicast
]);

// --------------------------------------------------
// BlockList initialization
// --------------------------------------------------

const BLOCK4 = new net.BlockList();
const BLOCK6 = new net.BlockList();

for (const [address, prefix] of BLOCKED_IPV4_RANGES) {
  BLOCK4.addSubnet(address, prefix, 'ipv4');
}

for (const [address, prefix] of BLOCKED_IPV6_RANGES) {
  BLOCK6.addSubnet(address, prefix, 'ipv6');
}

// --------------------------------------------------
// IPv4-mapped IPv6 handling
// --------------------------------------------------

function extractMappedIPv4(ip) {
  if (!net.isIPv6(ip)) {
    return null;
  }

  const normalized = ip.toLowerCase();

  // Dotted-decimal IPv4-mapped representation.
  const dottedMatch = normalized.match(
    /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/
  );

  if (dottedMatch && net.isIPv4(dottedMatch[1])) {
    return dottedMatch[1];
  }

  // Hexadecimal IPv4-mapped representation.
  // Example: ::ffff:7f00:1 = 127.0.0.1
  const hexMatch = normalized.match(
    /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/
  );

  if (!hexMatch) {
    return null;
  }

  const high = Number.parseInt(hexMatch[1], 16);
  const low = Number.parseInt(hexMatch[2], 16);

  return [
    high >> 8,
    high & 255,
    low >> 8,
    low & 255,
  ].join('.');
}

// --------------------------------------------------
// IP validation
// --------------------------------------------------

function isPrivateIp(ip) {
  if (
    typeof ip !== 'string' ||
    !ip ||
    ip.includes('%')
  ) {
    return true;
  }

  try {
    if (net.isIPv4(ip)) {
      return BLOCK4.check(ip, 'ipv4');
    }

    if (net.isIPv6(ip)) {
      // Explicitly validate IPv4-mapped addresses.
      const mappedIPv4 = extractMappedIPv4(ip);

      if (mappedIPv4) {
        return isPrivateIp(mappedIPv4);
      }

      return BLOCK6.check(ip, 'ipv6');
    }
  } catch {
    return true;
  }

  // Fail closed for invalid addresses.
  return true;
}

// --------------------------------------------------
// Hostname validation
// --------------------------------------------------

function isValidHostname(host) {
  return (
    typeof host === 'string' &&
    host.length <= 253 &&
    HOST_RE.test(host) &&
    !BLOCKED_DOMAINS_RE.test(host)
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

  // Direct IP address.
  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      throw blocked(
        'Private or reserved IP addresses are not allowed'
      );
    }

    return [host];
  }

  // Reject URLs, ports, credentials, paths, reserved domains and malformed names.
  if (!isValidHostname(host)) {
    throw blocked('Invalid hostname');
  }

  let addresses;

  try {
    // NOSONAR: Hostname destination is strictly validated by HOST_RE and BLOCKED_DOMAINS_RE
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

  // Reject the complete hostname if any result is invalid
  // or belongs to a prohibited address range.

  for (const entry of addresses) {
    if (
      !entry ||
      typeof entry.address !== 'string' ||
      !net.isIP(entry.address) ||
      isPrivateIp(entry.address)
    ) {
      throw blocked(
        'Host resolves to a private or reserved address'
      );
    }
  }

  // Remove duplicates after validation.
  return [
    ...new Set(
      addresses.map(({ address }) => address)
    ),
  ];
}

// --------------------------------------------------
// Exports
// --------------------------------------------------

module.exports = {
  isPrivateIp,
  isBlockedIp: isPrivateIp,
  isValidHostname,
  resolvePublic,
  HOST_RE,
};