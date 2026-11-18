/**
 * Network policy: the gate must never become a server-side request forgery
 * primitive. Every hop of every fetch is checked against this before any
 * connection is made.
 *
 * Blocks: loopback, private (RFC 1918), link-local (169.254/16, which
 * includes cloud metadata at 169.254.169.254), carrier-grade NAT, multicast,
 * reserved, unspecified; the IPv6 equivalents; IPv4-mapped IPv6; and any
 * hostname that resolves to one of those. Literal IP hosts are checked
 * directly. Ports are limited to 80/443 and an allowlist.
 */

import { promises as dns } from "node:dns";
import { isIP } from "node:net";

export interface NetPolicy {
  /** hostnames (exact or `.suffix`) that may never be fetched */
  denyHosts: string[];
  /** when non-empty, only these hostnames (exact or `.suffix`) may be fetched */
  allowHosts: string[];
  /** ports allowed besides 80 and 443 */
  extraPorts: number[];
  /** allow private/loopback targets (local development only; never in production) */
  allowPrivate: boolean;
}

export const DEFAULT_NET_POLICY: NetPolicy = { denyHosts: [], allowHosts: [], extraPorts: [], allowPrivate: false };

export class NetPolicyError extends Error {
  constructor(message: string, public readonly code: "private_address" | "denied_host" | "not_allowed_host" | "bad_port" | "unresolvable") {
    super(message);
  }
}

function ipv4ToInt(ip: string): number {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
function inCidr4(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

const BLOCKED_V4 = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
  "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
  "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
];

export function isPrivateIPv4(ip: string): boolean {
  return BLOCKED_V4.some((c) => inCidr4(ip, c));
}

/** Expand an IPv6 literal to its 8 groups (lower-case hex, no leading zeros), so every spelling compares alike. */
function expandIPv6(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/%.*$/, ""); // drop a zone id (fe80::1%en0)
  // a dotted IPv4 tail (::ffff:127.0.0.1) becomes two groups
  const v4 = s.match(/^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b, c, d] = v4.slice(2).map(Number);
    if ([a, b, c, d].some((n) => n > 255)) return null;
    s = `${v4[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

const v4From = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

export function isPrivateIPv6(ip: string): boolean {
  // Every spelling of an address must give the same answer: 0:0:0:0:0:0:0:1, ::ffff:127.0.0.1 and
  // ::ffff:7f00:1 are all loopback. An address that cannot be parsed is treated as blocked.
  const g = expandIPv6(ip);
  if (!g) return true;
  const zeros = (n: number) => g.slice(0, n).every((x) => x === 0);
  if (zeros(8)) return true; // ::
  if (zeros(7) && g[7] === 1) return true; // ::1
  if (zeros(5) && g[5] === 0xffff) return isPrivateIPv4(v4From(g[6], g[7])); // IPv4-mapped ::ffff:a.b.c.d
  if (zeros(6)) return isPrivateIPv4(v4From(g[6], g[7])); // IPv4-compatible ::a.b.c.d (deprecated, still parsed)
  if (g[0] === 0x2002) return isPrivateIPv4(v4From(g[1], g[2])); // 6to4 carries an IPv4 address
  if (g[0] === 0x64 && g[1] === 0xff9b) return true; // NAT64 well-known prefix can reach v4 space
  if ((g[0] & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g[0] & 0xffc0) === 0xfec0) return true; // site-local fec0::/10 (deprecated, still private by intent)
  if ((g[0] & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  if (g[0] === 0x2001 && g[1] === 0xdb8) return true; // documentation
  return false;
}

export function isPrivateIP(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return isPrivateIPv4(ip);
  if (v === 6) return isPrivateIPv6(ip);
  return true; // not an IP at all: treat as blocked
}

function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith(".")) return h === p.slice(1) || h.endsWith(p);
  return h === p;
}

/**
 * Validate one hop. Returns the resolved addresses so the caller can pin
 * them (DNS rebinding defense: the fetch must connect to what we checked).
 */
export async function checkTarget(url: URL, policy: NetPolicy, resolver: (host: string) => Promise<string[]> = defaultResolve): Promise<string[]> {
  // one spelling per host: no brackets, no trailing dot ("localhost." is localhost), lower case
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  if (port !== 80 && port !== 443 && !policy.extraPorts.includes(port)) {
    throw new NetPolicyError(`port ${port} not allowed`, "bad_port");
  }
  if (policy.denyHosts.some((p) => hostMatches(host, p))) throw new NetPolicyError(`host ${host} is denied by policy`, "denied_host");
  if (policy.allowHosts.length && !policy.allowHosts.some((p) => hostMatches(host, p))) throw new NetPolicyError(`host ${host} is not in the allowlist`, "not_allowed_host");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".arpa")) {
    if (!policy.allowPrivate) throw new NetPolicyError(`host ${host} is local`, "private_address");
  }

  let addrs: string[];
  if (isIP(host)) addrs = [host];
  else {
    try { addrs = await resolver(host); } catch { throw new NetPolicyError(`cannot resolve ${host}`, "unresolvable"); }
    if (!addrs.length) throw new NetPolicyError(`cannot resolve ${host}`, "unresolvable");
  }
  if (!policy.allowPrivate) {
    for (const a of addrs) if (isPrivateIP(a)) throw new NetPolicyError(`${host} resolves to blocked address ${a}`, "private_address");
  }
  return addrs;
}

async function defaultResolve(host: string): Promise<string[]> {
  const res = await dns.lookup(host, { all: true, verbatim: true });
  return res.map((r) => r.address);
}
