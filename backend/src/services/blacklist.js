'use strict';
const dns = require('dns');
const net = require('net');
const { resolvePublic, isValidHostname } = require('./netguard');

const resolver = new dns.promises.Resolver({ timeout: 4000, tries: 1 });

const IP_LISTS = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN' },
  { zone: 'b.barracudacentral.org', name: 'Barracuda' },
  { zone: 'bl.spamcop.net', name: 'SpamCop' },
  { zone: 'psbl.surriel.com', name: 'Passive Spam Block List' },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT L1' },
  { zone: 'dnsbl.dronebl.org', name: 'DroneBL' },
  { zone: 'bl.mailspike.net', name: 'Mailspike' },
  { zone: 'ix.dnsbl.manitu.net', name: 'Manitu (NiX Spam)' },
  { zone: 'all.s5h.net', name: 's5h.net' },
];

const DOMAIN_LISTS = [
  { zone: 'dbl.spamhaus.org', name: 'Spamhaus DBL' },
  { zone: 'multi.surbl.org', name: 'SURBL' },
  { zone: 'multi.uribl.com', name: 'URIBL' },
];

function reverseIPv4(ip) {
  return ip.split('.').reverse().join('.');
}

async function queryZone(query, list) {
  const base = { zone: list.zone, name: list.name };
  try {
    const answers = await resolver.resolve4(`${query}.${list.zone}`);
    const code = answers[0];
    // Spamhaus & others return 127.255.255.x when the resolver is blocked/over quota.
    if (code.startsWith('127.255.255.')) {
      return { ...base, status: 'unknown', returnCode: code, reason: 'Query refused (public resolver blocked or quota exceeded)' };
    }
    let reason;
    try {
      reason = (await resolver.resolveTxt(`${query}.${list.zone}`)).map((c) => c.join('')).join(' ').slice(0, 300);
    } catch { /* TXT is optional */ }
    return { ...base, status: 'listed', returnCode: code, reason };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { ...base, status: 'clean' };
    return { ...base, status: 'unknown', reason: e.code || 'Lookup failed' };
  }
}

async function checkIp(ip) {
  if (!net.isIPv4(ip)) {
    const e = new Error('Only IPv4 addresses are supported for IP blacklists');
    e.code = 'BAD_INPUT';
    throw e;
  }
  const q = reverseIPv4(ip);
  const results = await Promise.all(IP_LISTS.map((l) => queryZone(q, l)));
  return { type: 'ip', target: ip, results };
}

async function checkDomain(domain) {
  const results = await Promise.all(DOMAIN_LISTS.map((l) => queryZone(domain, l)));
  return { type: 'domain', target: domain, results };
}

function summarize(entries) {
  const all = entries.flatMap((e) => e.results);
  const listed = all.filter((r) => r.status === 'listed').length;
  const unknown = all.filter((r) => r.status === 'unknown').length;
  return { checked: all.length, listed, clean: all.length - listed - unknown, unknown };
}

// target may be an IPv4 address or a domain (domain: checks domain lists + its A records).
async function check(target) {
  target = String(target || '').trim().toLowerCase();
  const entries = [];
  if (net.isIPv4(target)) {
    await resolvePublic(target);
    entries.push(await checkIp(target));
  } else if (isValidHostname(target)) {
    entries.push(await checkDomain(target));
    let ips = [];
    try { ips = await resolver.resolve4(target); } catch { /* no A record */ }
    for (const ip of ips.slice(0, 3)) entries.push(await checkIp(ip));
  } else {
    const e = new Error('Enter a valid IPv4 address or domain name');
    e.code = 'BAD_INPUT';
    throw e;
  }
  return { target, checkedAt: new Date().toISOString(), summary: summarize(entries), entries };
}

module.exports = { check, checkIp, checkDomain };
