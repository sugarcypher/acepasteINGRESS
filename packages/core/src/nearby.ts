/**
 * Nearby: what devices around you say about themselves.
 *
 * A Bonjour service name, a Bluetooth device name, a printer's description, a beacon's link: each is a string
 * chosen by whoever owns the device, broadcast to everyone in range, and shown in pickers and lists that an
 * agent may read ("which printer should I use?", "what's on this network?"). Nobody vouches for any of it.
 * It is the lowest-trust content there is (trust level 6), and it is read here as content, never as fact.
 *
 * Checks:
 *   instructions in a name or a record    the ordinary rules and the classifier's short-text mode
 *   authority names                       "IT Managed Printer", "Apple Setup", "System Update Service"
 *   lookalikes                            a name one or two characters from a device you know, or the same
 *                                         name from a different address
 *   links                                 a beacon's or a service's URL is listed, never opened; ones that hide
 *                                         their destination are flagged
 *   oversized fields                      a TXT record or a name far longer than a device needs
 *
 * Ingress cannot stop a broadcast. It gates what an agent reads of it.
 */

import { execFile } from "node:child_process";
import type { Finding, TextSegment } from "./types.js";
import { decodeEntities, type AdapterResult } from "./adapters.js";
import { linkTrick } from "./messages.js";

export interface NearbyRecord {
  type: "bonjour" | "bluetooth" | "printer" | "beacon" | "wifi" | "other";
  name: string;
  /** the service type or device class: "_ipp._tcp", "Keyboard" */
  service?: string;
  /** an address that identifies the device: host, MAC, UUID */
  address?: string;
  /** key and value pairs the device publishes (Bonjour TXT, printer make and location) */
  fields?: Record<string, string>;
  url?: string;
  /** paired, connected or added by the person: still its own words, but a device they chose */
  known?: boolean;
}
export interface NearbyHints { /** names of devices the person knows, for lookalike checks: { name, address? } */ knownDevices?: Array<{ name: string; address?: string }> }

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");
const TYPES = new Set(["bonjour", "bluetooth", "printer", "beacon", "wifi", "other"]);

export function looksLikeNearbyJson(doc: unknown): boolean {
  const list = Array.isArray(doc) ? doc : doc && typeof doc === "object" && Array.isArray((doc as Json).devices) ? ((doc as Json).devices as unknown[]) : undefined;
  return !!list?.length && list.slice(0, 30).every((r) => !!r && typeof r === "object" && typeof (r as Json).name === "string" && typeof (r as Json).type === "string" && TYPES.has(String((r as Json).type)));
}

export function parseNearby(doc: unknown): NearbyRecord[] {
  const list = Array.isArray(doc) ? doc : doc && typeof doc === "object" ? ((doc as Json).devices ?? (doc as Json).records ?? (doc as Json).services) : undefined;
  const out: NearbyRecord[] = [];
  for (const r of (Array.isArray(list) ? list : []).slice(0, 2000)) {
    if (!r || typeof r !== "object") continue;
    const o = r as Json;
    const name = str(o.name) || str(o.device_name) || str(o.ssid);
    if (!name) continue;
    const fields: Record<string, string> = {};
    for (const src of [o.txt, o.fields, o.attributes]) if (src && typeof src === "object") for (const [k, v] of Object.entries(src as Json).slice(0, 60)) if (str(v)) fields[k] = str(v);
    for (const k of ["location", "description", "info", "make_and_model", "manufacturer", "model", "note"]) if (str(o[k])) fields[k] = str(o[k]);
    out.push({ type: TYPES.has(str(o.type)) ? (str(o.type) as NearbyRecord["type"]) : "other", name, service: str(o.service) || undefined, address: str(o.address) || str(o.host) || str(o.mac) || undefined, fields: Object.keys(fields).length ? fields : undefined, url: str(o.url) || undefined, known: o.known === true || o.paired === true || o.connected === true });
  }
  return out;
}

// ---------- reading what the system lists (macOS; read-only) ----------

/** `dns-sd -B <type>` lines: "Timestamp A/R Flags if Domain Service-Type Instance-Name" */
export function parseDnsSdBrowse(text: string): NearbyRecord[] {
  const out: NearbyRecord[] = [];
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*\d{1,2}:\d{2}:\d{2}\.\d+\s+Add\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(.+?)\s*$/);
    // (the domain column, "local.", is not an address: a browse does not say which host a service is on)
    if (m) out.push({ type: "bonjour", name: m[3], service: m[2].replace(/\.$/, "") });
  }
  return out;
}

/** `system_profiler SPBluetoothDataType -json` */
export function parseBluetoothProfile(json: string): NearbyRecord[] {
  const out: NearbyRecord[] = [];
  let doc: unknown;
  try { doc = JSON.parse(json); } catch { return out; }
  for (const ctl of ((doc as Json)?.SPBluetoothDataType as Json[] | undefined) ?? []) {
    for (const [key, known] of [["device_connected", true], ["device_not_connected", true], ["devices_list", false]] as const) {
      for (const entry of (ctl[key] as Json[] | undefined) ?? []) {
        for (const [name, info] of Object.entries(entry)) {
          const i = (info ?? {}) as Json;
          out.push({ type: "bluetooth", name, service: str(i.device_minorType) || undefined, address: str(i.device_address) || undefined, known, fields: str(i.device_vendorID) ? { vendor: str(i.device_vendorID) } : undefined });
        }
      }
    }
  }
  return out;
}

/** `lpstat -l -p` blocks: "printer NAME ..." followed by indented "Description:", "Location:" lines */
export function parseLpstatPrinters(text: string): NearbyRecord[] {
  const out: NearbyRecord[] = [];
  let cur: NearbyRecord | undefined;
  for (const line of text.split("\n")) {
    const p = line.match(/^printer\s+(\S+)/);
    if (p) { cur = { type: "printer", name: p[1], known: true, fields: {} }; out.push(cur); continue; }
    const f = line.match(/^\s+(Description|Location|Interface|Alerts|Connection):\s*(.+)$/);
    if (cur && f && f[2].trim()) cur.fields![f[1].toLowerCase()] = f[2].trim();
  }
  return out;
}

const run = (cmd: string, args: string[], timeoutMs: number): Promise<string> => new Promise((resolve) => {
  // dns-sd never exits on its own: it is stopped when the time is up, and what it printed is kept
  execFile(cmd, args, { timeout: timeoutMs, encoding: "utf8", maxBuffer: 16 * 1024 * 1024, killSignal: "SIGTERM" }, (_err, stdout) => resolve(String(stdout ?? "")));
});

/** What this Mac currently lists: Bonjour services, Bluetooth devices, printers. Read-only; nothing is joined, paired or contacted. */
export async function collectNearby(opts: { seconds?: number } = {}): Promise<NearbyRecord[]> {
  if (process.platform !== "darwin") return [];
  const ms = Math.max(1, opts.seconds ?? 3) * 1000;
  const types = parseDnsSdBrowse(await run("/usr/bin/dns-sd", ["-B", "_services._dns-sd._udp", "local."], ms)).map((r) => `${r.name}.${(r.service ?? "").replace(/\.local$/, "")}`).filter((t) => /^_[\w-]+\._(tcp|udp)$/.test(t)).slice(0, 40);
  const browsed = await Promise.all([...new Set(types)].map((t) => run("/usr/bin/dns-sd", ["-B", t, "local."], ms)));
  const [bt, lp] = await Promise.all([run("/usr/sbin/system_profiler", ["SPBluetoothDataType", "-json"], 20_000), run("/usr/bin/lpstat", ["-l", "-p"], 10_000)]);
  return [...browsed.flatMap(parseDnsSdBrowse), ...parseBluetoothProfile(bt), ...parseLpstatPrinters(lp)];
}

// ---------- checks ----------

const AUTHORITY = /\b(?:it[- ]?(?:managed|admin|support|department)|admin(?:istrator)?|system (?:update|service|setup|recovery)|security (?:update|scanner|service)|(?:apple|microsoft|google|windows|macos|ios) (?:setup|support|update|security|recovery|configurator)|device (?:enrollment|management)|mdm|corporate (?:vpn|wifi|network)|free (?:public )?wi-?fi|guest wi-?fi login|software update|firmware update|setup assistant|recovery mode|password (?:reset|recovery))\b/i;

function distance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let last = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) { const t = prev[j]; prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, last + (a[i - 1] === b[j - 1] ? 0 : 1)); last = t; }
  }
  return prev[b.length];
}
/** the name with lookalike characters folded, so "Offíce-Printer" and "Office-Printer" compare equal */
const fold = (s: string) => s.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[0oо]/g, "o").replace(/[1lIіı|]/g, "l").replace(/[аa]/g, "a").replace(/[еe]/g, "e").replace(/[\s_\-.’']+/g, "");

export function adaptNearby(raw: string, hints: NearbyHints = {}): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "pass" | "action">) => findings.push({ pass: "channel", action: "none", ...f });
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { doc = undefined; }
  if (doc === undefined || typeof doc !== "object") {
    // a plain list of names, one per line
    segments.push({ text: decodeEntities(typeof doc === "string" ? doc : raw).text, visibility: "visible", path: "nearby/text" });
    return { segments, findings };
  }
  const records = parseNearby(doc);
  const known: Array<{ name: string; address?: string; type?: string }> = [...(hints.knownDevices ?? []), ...records.filter((r) => r.known).map((r) => ({ name: r.name, address: r.address, type: r.type }))];
  // One device shows up in several lists (an iPad over Bluetooth and again over Bonjour), and stock names repeat
  // in every office ("iPad", "HP LaserJet"). The same name at another address means something only within one
  // kind of listing, and only for a name someone chose. (Found on the first live run: this Mac's own iPad.)
  const stock = /^(?:i(?:Pad|Phone|Mac)|Mac(?:Book(?: Pro| Air)?| mini| Studio| Pro)?|AirPods(?: Pro| Max)?|Apple (?:Watch|TV)|HomePod(?: mini)?|Android|Galaxy\b.*|Pixel\b.*|HP\b.*|Brother\b.*|Canon\b.*|EPSON\b.*|Chromecast.*|Living Room|Bedroom|Kitchen|Office)$/i;
  let authority = 0, lookalike = 0, oversized = 0, links = 0;
  records.forEach((r, i) => {
    const path = `nearby[${i}]:${r.type}`;
    segments.push({ text: r.name, visibility: "visible", path: `${path}/name` });
    for (const [k, v] of Object.entries(r.fields ?? {})) {
      // a device's extra records are shown by few pickers: read, and judged as text nobody chose to look at
      segments.push({ text: v, visibility: "attribute", path: `${path}/${k}` });
      if (v.length > 400 && oversized++ < 3) add({ kind: "nearby.oversized_field", confidence: 0.3, severity: 0.5, message: `a ${r.type} device publishes ${v.length} characters in its "${k.slice(0, 30)}" record: far more than a device needs to describe itself`, location: `${path}/${k}`, inHidden: true });
    }
    if (r.name.length > 120 && oversized++ < 3) add({ kind: "nearby.oversized_field", confidence: 0.3, severity: 0.5, message: `a ${r.type} device has a ${r.name.length}-character name`, location: `${path}/name` });
    if (!r.known && AUTHORITY.test(`${r.name} ${Object.values(r.fields ?? {}).join(" ")}`) && authority++ < 5) add({ kind: "nearby.authority_name", confidence: 0.35, severity: 0.6, message: `a ${r.type} device nobody here set up calls itself "${r.name.slice(0, 60)}": anyone in range can broadcast that name`, location: `${path}/name` });
    if (!r.known) {
      const twin = known.find((k) => k.name !== r.name ? fold(k.name) === fold(r.name) || (Math.min(k.name.length, r.name.length) >= 6 && distance(k.name.toLowerCase(), r.name.toLowerCase()) <= 1) : !!k.address && !!r.address && k.address.toLowerCase() !== r.address.toLowerCase() && (!k.type || k.type === r.type) && !stock.test(r.name.trim()));
      if (twin && lookalike++ < 5) add({ kind: "nearby.lookalike", confidence: 0.45, severity: 0.65, message: twin.name === r.name ? `a second device is using the name of one you know ("${r.name.slice(0, 60)}") from a different address` : `"${r.name.slice(0, 60)}" is nearly the name of a device you know ("${twin.name.slice(0, 60)}")`, location: `${path}/name` });
    }
    const url = r.url ?? Object.values(r.fields ?? {}).find((v) => /^https?:\/\//i.test(v));
    if (url) {
      const trick = linkTrick(url);
      segments.push({ text: `[${r.type} link: ${url.slice(0, 200)}]`, visibility: "attribute", path: `${path}/url` });
      if (trick && links++ < 5) add({ kind: "nearby.link", confidence: 0.4, severity: 0.6, message: `a ${r.type} device broadcasts a link that is ${trick}. Links from devices are listed, never opened`, location: `${path}/url` });
    }
  });
  return { segments, findings };
}
