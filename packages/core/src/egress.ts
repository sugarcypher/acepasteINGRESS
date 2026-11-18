/**
 * Egress: what an agent sends out, judged with what it has read.
 *
 * A firewall sees a connection. The broker sees the action and remembers the content the run took in, so it
 * can say why an action is happening: "this address came from the email you read two minutes ago". These are
 * the checks on the way out. Each returns reasons in plain words; the broker turns them into a decision.
 *
 *   one-time codes   A verification code the run read (in a message, a notification, a page) is for the person.
 *                    An action that carries it to a destination that came from outside content is refused;
 *                    anywhere else, a person is asked and told what the action carries.
 *   credentials      A recognisable credential in outbound arguments, once the run has read outside content.
 *   provenance       A destination that first appeared in content the run read, not in anything the person
 *                    said. Not a refusal on its own (following a link is normal); it is named in the approval
 *                    request and makes data-bearing requests to it need a person.
 *   known-bad        A destination on a local blocklist (malware and botnet controllers) is refused.
 *   calling home     Many requests in a short time to a host the run met in outside content.
 *   peripherals      Printing, copying to a removable drive, AirDrop, Bluetooth transfer: ways out of the
 *                    machine that never touch the network.
 *   local tunnels    A loopback port owned by a tunnel or proxy program is the internet, not this machine.
 *
 * Scope, stated plainly: detect, refuse, record. Nothing here contacts, probes or acts against a destination.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { stateDir } from "./changes.js";
import { collectSecrets } from "./secrets.js";

// ---------- one-time codes ----------

// "code" alone is too common a word (zip code, error code, the token limit is 8192): a number is taken as a
// verification code only when the words around it say so.
const KIND = String.raw`(?:verification|security|confirmation|log-?in|sign-?in|one[- ]time|authenti[cs]ation|access|auth|2fa|mfa|two[- ]factor)`;
const NUM = String.raw`(\d[\d -]{2,9}\d)`;
const NOT_THAT_CODE = String.raw`(?<!\b(?:zip|postal|post|area|country|error|status|exit|promo|discount|coupon|voucher|source|colou?r|product|tracking|reference|order|bar|qr|dial|dialing|sort|branch|tax|response|return|result|http|key|the|this|some|of)\s)`;
const CODE_PATTERNS = [
  // "your verification code is 482913", "security code: 482 913"
  new RegExp(String.raw`\b${KIND}\s+(?:code|pin|passcode|password)\b[^.\n\d]{0,40}?\b${NUM}\b`, "gi"),
  // "OTP 482913", "one-time password is 482913"
  new RegExp(String.raw`\b(?:otp|passcode|one[- ]time (?:password|passcode|pin))\b[^.\n\d]{0,40}?\b${NUM}\b`, "gi"),
  // "482913 is your Example verification code"
  new RegExp(String.raw`\b${NUM}\b[^.\n\d]{0,30}?\bis your\b[^.\n]{0,40}?\b(?:code|otp|passcode|pin)\b`, "gi"),
  // "Your code is 482913", "Code: 482913", "PIN: 4821"
  new RegExp(String.raw`${NOT_THAT_CODE}\b(?:code|pin)\s*(?:is|:)\s*${NUM}\b`, "gi"),
  // an alphanumeric code is taken only right after the words, in the shape codes have (the check below wants capitals and a digit)
  new RegExp(String.raw`\b${KIND}\s+code\s*(?:is|:)?\s*\b([A-Za-z0-9]{6,10})\b`, "gi"),
];

/** Verification codes stated in a text ("Your code is 482913"). Digits only, 4 to 8 of them, or a 6-10 character code right after the words. */
export function oneTimeCodes(text: string): string[] {
  const out = new Set<string>();
  for (const re of CODE_PATTERNS) {
    for (const m of text.slice(0, 200_000).matchAll(re)) {
      const raw = m[1];
      const digits = raw.replace(/[ -]/g, "");
      if (/^\d{4,8}$/.test(digits)) { if (!/^(19|20)\d\d$/.test(digits)) out.add(digits); } // a year is not a code
      else if (/^[A-Z0-9]{6,10}$/.test(raw) && /\d/.test(raw) && /[A-Z]/.test(raw)) out.add(raw);
    }
  }
  return [...out];
}

/** Does any outbound string carry one of these codes, written plainly or with separators? */
export function carriesCode(strings: readonly string[], codes: readonly string[]): string | undefined {
  if (!codes.length) return undefined;
  for (const s of strings) {
    const squeezed = s.replace(/(?<=\d)[ -](?=\d)/g, "");
    for (const c of codes) {
      // the code as a whole token: not a longer number that happens to contain it
      const re = new RegExp(`(?<![A-Za-z0-9])${c}(?![A-Za-z0-9])`);
      if (re.test(s) || re.test(squeezed)) return c;
    }
  }
  return undefined;
}

// ---------- credentials ----------

/** Kinds of credential found in outbound strings (never the values). */
export function credentialsLeaving(strings: readonly string[]): number {
  return collectSecrets(strings.filter((s) => s.length <= 100_000)).length;
}

// ---------- hosts in content ----------

const HOST_IN_TEXT = /(?:https?:\/\/|\/\/)([a-z0-9.-]+\.[a-z]{2,24})|(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|ai|co|me|info|biz|xyz|site|online|top|cloud|sh|to|cc|link|click|page|tech|store|live|example))(?![\w-])|@([a-z0-9.-]+\.[a-z]{2,24})\b/gi;

/** Hosts a text names: in links, as bare domains with common endings, and after @ in addresses. */
export function hostsMentioned(text: string, limit = 400): string[] {
  const out = new Set<string>();
  for (const m of text.slice(0, 500_000).matchAll(HOST_IN_TEXT)) {
    const h = (m[1] ?? m[2] ?? m[3] ?? "").toLowerCase().replace(/\.$/, "");
    if (h && h.includes(".")) out.add(h);
    if (out.size >= limit) break;
  }
  return [...out];
}

// ---------- blocklists ----------

function ipv4ToInt(ip: string): number { const p = ip.split(".").map(Number); return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0; }

/**
 * Known-bad destinations, from plain-text lists a person or `ingress blocklist update` put in
 * <state>/blocklists/*.txt: one host, IP address, IPv4 CIDR or URL per line; `#` and `;` start comments; a
 * hosts-file line ("0.0.0.0 bad.example") is read for its name. Nothing is fetched here.
 */
export class Blocklist {
  private hosts = new Set<string>();
  private ips = new Set<string>();
  private cidrs: Array<{ base: number; mask: number; label: string }> = [];
  readonly sources: string[] = [];

  static load(dir: string = join(stateDir(), "blocklists")): Blocklist {
    const b = new Blocklist();
    if (!existsSync(dir)) return b;
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".txt")).sort()) {
      try { b.add(readFileSync(join(dir, f), "utf8"), f); } catch { /* an unreadable list adds nothing */ }
    }
    return b;
  }

  add(text: string, source = "inline"): number {
    let n = 0;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/[#;].*$/, "").trim().toLowerCase();
      if (!line) continue;
      // a list of URLs is read for its hosts
      const asUrl = line.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^\s/@]*@)?(\[[0-9a-f:.]+\]|[^\s/:?#]+)/);
      const tokens = asUrl ? [asUrl[1].replace(/^\[|\]$/g, "")] : line.split(/\s+/);
      // hosts-file form: an address, then names
      const entries = tokens.length > 1 && isIP(tokens[0]) && /^(0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(tokens[0]) ? tokens.slice(1) : [tokens[0]];
      for (const e of entries) {
        const cidr = e.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
        if (cidr && isIP(cidr[1]) === 4 && Number(cidr[2]) >= 8 && Number(cidr[2]) <= 32) {
          const bits = Number(cidr[2]);
          const mask = (~0 << (32 - bits)) >>> 0;
          this.cidrs.push({ base: (ipv4ToInt(cidr[1]) & mask) >>> 0, mask, label: e }); n++;
        } else if (isIP(e)) { this.ips.add(e); n++; }
        else if (/^[a-z0-9.-]+\.[a-z]{2,24}$/.test(e) && e !== "localhost.localdomain") { this.hosts.add(e.replace(/^\*\./, "")); n++; }
      }
    }
    if (n) this.sources.push(`${source} (${n})`);
    return n;
  }

  get size(): number { return this.hosts.size + this.ips.size + this.cidrs.length; }

  /** The entry that matches this host or address, or undefined. A listed name covers its subdomains. */
  match(host: string): string | undefined {
    const h = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (isIP(h)) {
      if (this.ips.has(h)) return h;
      if (isIP(h) === 4) { const n = ipv4ToInt(h); const c = this.cidrs.find((x) => ((n & x.mask) >>> 0) === x.base); if (c) return c.label; }
      return undefined;
    }
    const labels = h.split(".");
    for (let i = 0; i < labels.length - 1; i++) { const s = labels.slice(i).join("."); if (this.hosts.has(s)) return s; }
    return undefined;
  }
}

/** Free lists `ingress blocklist update` can download. The CLI fetches them; this module only names them. */
export const BLOCKLIST_FEEDS: ReadonlyArray<{ name: string; url: string; what: string; terms: string }> = [
  { name: "feodo-ips", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", what: "botnet command-and-control addresses (abuse.ch Feodo Tracker)", terms: "CC0" },
  { name: "spamhaus-drop", url: "https://www.spamhaus.org/drop/drop.txt", what: "networks run by spam and crime operations (Spamhaus DROP)", terms: "free to use with attribution; see spamhaus.org" },
  { name: "et-compromised", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", what: "addresses seen attacking others (Emerging Threats Open)", terms: "Emerging Threats Open ruleset terms" },
];
// Checked 2026-11-18: abuse.ch's host lists (URLhaus, ThreatFox) now answer 410 without an account key, so they
// are not in the default set. Anyone with a key, or any other list, can save a file into <state>/blocklists.

// ---------- peripherals ----------

export interface PeripheralEgress { way: "print" | "removable-drive" | "airdrop" | "bluetooth" | "burn"; why: string }

/** Does this action move data off the machine without the network? */
export function peripheralEgress(tool: string, strings: readonly string[]): PeripheralEgress[] {
  const out = new Map<string, PeripheralEgress>();
  const add = (way: PeripheralEgress["way"], why: string) => { if (!out.has(way)) out.set(way, { way, why }); };
  const name = tool.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-.:/]+/g, " ").toLowerCase();
  if (/\b(print|printer|lpr)\b/.test(name)) add("print", "it sends a document to a printer");
  if (/\bair ?drop\b/.test(name)) add("airdrop", "it sends a file over AirDrop");
  if (/\bbluetooth\b[^|]*\b(send|transfer|push)\b|\b(send|transfer|push)\b[^|]*\bbluetooth\b/.test(name)) add("bluetooth", "it sends a file over Bluetooth");
  for (const s of strings) {
    if (s.length > 20_000) continue;
    if (/(?:^|[;&|(\s])(?:lp|lpr)\s+(?!-[a-z]*[lq]\b)[^\n]*\S|\bcupsenable\b|\blpadmin\s+-p\b/.test(s)) add("print", "it prints, or adds a printer");
    if (/(?:^|[;&|(\s])(?:cp|mv|rsync|ditto|dd|tar|zip|scp)\b[^\n]*\s\/Volumes\/(?!Macintosh HD\b)[^\s/]+/.test(s) || /(?:^|[;&|(\s])(?:cp|mv|rsync|dd)\b[^\n]*\s\/(?:media|mnt|run\/media)\/\S+/.test(s) || /\b(?:of|to)=\/dev\/(?:r?disk\d|sd[a-z])/.test(s)) add("removable-drive", "it copies data to a removable or external drive");
    if (/\bAirDrop\b/i.test(s) && /\b(osascript|open|shortcuts|sharing)\b/i.test(s)) add("airdrop", "it sends a file over AirDrop");
    if (/\bblueutil\b[^\n]*--(?:send|connect)|\bbluetooth-sendto\b|\bobexftp\b|\bussp-push\b/.test(s)) add("bluetooth", "it sends a file over Bluetooth");
    if (/\b(?:hdiutil\s+burn|drutil\s+burn|growisofs|wodim|cdrecord)\b/.test(s)) add("burn", "it writes data to a disc");
  }
  return [...out.values()];
}

// ---------- local tunnels ----------

const TUNNEL_PROGRAMS = /^(ngrok|cloudflared|frpc|bore|lt|localtunnel|devtunnel|zrok|pinggy|chisel|inlets|tailscaled?|ssh|autossh|socat|stunnel|squid|privoxy|tinyproxy|mitmproxy|mitmdump|proxychains4?|tor|v2ray|xray|sing-box|clash|shadowsocks.*|ss-local)$/i;

/** Loopback ports named in the arguments ("localhost:8080", "http://127.0.0.1:1080/x", "nc 127.0.0.1 9050"). */
export function loopbackPorts(strings: readonly string[]): number[] {
  const out = new Set<number>();
  for (const s of strings) {
    if (s.length > 20_000) continue;
    for (const m of s.matchAll(/(?:\b(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)|\[::1?\])[: ](\d{2,5})\b/gi)) { const p = Number(m[1]); if (p > 0 && p < 65536) out.add(p); }
  }
  return [...out];
}

/** True when the program that owns a local port forwards traffic elsewhere. */
export function isForwarder(program: string | undefined): boolean {
  return !!program && TUNNEL_PROGRAMS.test(program.split("/").pop() ?? program);
}

// ---------- calling home ----------

/** Requests per host within a window, for hosts the run met in outside content. */
export class HomeCalls {
  private at = new Map<string, number[]>();
  record(host: string, now: number): void { const a = (this.at.get(host) ?? []).filter((t) => now - t < 600_000); a.push(now); this.at.set(host, a); }
  count(host: string, now: number): number { return (this.at.get(host) ?? []).filter((t) => now - t < 600_000).length; }
  export(): Record<string, number[]> { return Object.fromEntries(this.at); }
  import(d: Record<string, number[]> | undefined): void { for (const [k, v] of Object.entries(d ?? {})) if (Array.isArray(v)) this.at.set(k, v.filter((x) => typeof x === "number").slice(-50)); }
}
