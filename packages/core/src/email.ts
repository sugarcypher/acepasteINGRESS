/**
 * Email (RFC 5322 / MIME text, and the JSON that Gmail, Microsoft Graph and most mail tools return).
 *
 * An email is the easiest way to put text in front of someone else's assistant: no click is needed, only
 * that the assistant reads the inbox. What makes the channel different from a web page:
 *
 *   - One message is several documents. A person's mail client shows the HTML part; a tool often reads the
 *     plain part, the snippet or the raw headers. Text that only the plain part has is text the person never
 *     saw: the email version of serving an AI fetcher a different page.
 *   - The sender describes themselves. A display name is free text ("IT Security Team"), Reply-To can point
 *     anywhere, and whether the message really came from its From domain is in the authentication results.
 *   - It fetches. Remote images and stylesheets load when a message is rendered, which is how a message
 *     carries data out (the image URL is the request). Ingress never loads them: they are listed.
 *   - Marketing mail hides text on purpose (a "preheader" shown only in the inbox list) and is full of
 *     tracking pixels. That is furniture: recorded, and never a refusal unless an instruction is in it.
 *
 * The adapter turns a message into segments with the visibility a person had of each piece, plus findings
 * about the message's own structure. Attachments it can read as text are read; the rest are listed as not
 * inspected, so a clean verdict never means "not looked at".
 */

import type { Finding, TextSegment } from "./types.js";
import { analyzeHtml } from "./visibility.js";
import { passagesOnlyIn } from "./served.js";
import { adaptCalendar } from "./calendar.js";

export interface EmailPart {
  contentType: string;
  params: Record<string, string>;
  headers: Map<string, string>;
  filename?: string;
  /** decoded text for text-like parts; undefined for parts that are not text */
  text?: string;
  bytes: number;
  parts: EmailPart[];
}

export interface EmailAdapterResult {
  segments: TextSegment[];
  findings: Finding[];
}

const MAX_DEPTH = 8, MAX_PARTS = 300;

// ---------- MIME ----------

function decodeWords(v: string): string {
  // RFC 2047: =?charset?B|Q?text?=, adjacent words joined without the space between them
  return v.replace(/(=\?[^?\s]+\?[bBqQ]\?[^?\s]*\?=)(\s+(?==\?))?/g, (_, w: string) => {
    const m = w.match(/^=\?([^?]+)\?([bBqQ])\?([^?]*)\?=$/);
    if (!m) return w;
    try {
      const bytes = m[2].toUpperCase() === "B" ? Buffer.from(m[3], "base64") : Buffer.from(m[3].replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_x, h: string) => String.fromCharCode(parseInt(h, 16))), "latin1");
      return new TextDecoder(m[1].replace(/\*.*$/, "").toLowerCase(), { fatal: false }).decode(bytes);
    } catch { return w; }
  });
}

function parseHeaders(block: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of block.replace(/\n[ \t]+/g, " ").split("\n")) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const name = line.slice(0, i).trim().toLowerCase();
    const value = decodeWords(line.slice(i + 1).trim());
    // repeated headers (Received, Authentication-Results) are kept together
    out.set(name, out.has(name) ? `${out.get(name)}\n${value}` : value);
  }
  return out;
}

function parseParams(v: string): { type: string; params: Record<string, string> } {
  const [type, ...rest] = v.split(/;(?=(?:[^"]*"[^"]*")*[^"]*$)/);
  const params: Record<string, string> = {};
  for (const p of rest) {
    const eq = p.indexOf("=");
    if (eq <= 0) continue;
    let k = p.slice(0, eq).trim().toLowerCase(), val = p.slice(eq + 1).trim().replace(/^"|"$/g, "");
    if (k.endsWith("*")) { // RFC 2231: name*=utf-8''percent-encoded
      k = k.slice(0, -1);
      const m = val.match(/^([^']*)'[^']*'(.*)$/);
      if (m) { try { val = decodeURIComponent(m[2]); } catch { val = m[2]; } }
    }
    params[k.replace(/\*\d+$/, "")] = (params[k.replace(/\*\d+$/, "")] ?? "") + decodeWords(val);
  }
  return { type: (type ?? "").trim().toLowerCase(), params };
}

function decodeBody(body: string, encoding: string, charset: string): { text: string; bytes: number } {
  let buf: Buffer;
  const enc = encoding.trim().toLowerCase();
  if (enc === "base64") buf = Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  else if (enc === "quoted-printable") {
    // =XX is one byte; anything else is itself. A body that carries raw non-ASCII characters (it should not,
    // but mail in the wild does) keeps them: they are written out as the UTF-8 they arrived as.
    const chunks: Buffer[] = [];
    const src = body.replace(/=\r?\n/g, "");
    let last = 0;
    for (const m of src.matchAll(/=([0-9A-Fa-f]{2})/g)) {
      if (m.index! > last) chunks.push(Buffer.from(src.slice(last, m.index), "utf8"));
      chunks.push(Buffer.from([parseInt(m[1], 16)]));
      last = m.index! + 3;
    }
    if (last < src.length) chunks.push(Buffer.from(src.slice(last), "utf8"));
    buf = Buffer.concat(chunks);
  }
  else return { text: body, bytes: Buffer.byteLength(body) }; // 7bit, 8bit, binary: already text as received
  let text: string;
  try { text = new TextDecoder(charset || "utf-8", { fatal: false }).decode(buf); } catch { text = buf.toString("utf8"); }
  return { text, bytes: buf.length };
}

const TEXTLIKE = /^(text\/|application\/(json|xml|xhtml\+xml|ics|x-ics|ld\+json|javascript|x-sh|x-yaml|yaml)|message\/rfc822)/;

function parsePart(raw: string, depth: number, budget: { n: number }): EmailPart {
  const split = raw.search(/\n\n/);
  const headBlock = split < 0 ? raw : raw.slice(0, split);
  const body = split < 0 ? "" : raw.slice(split + 2);
  const headers = parseHeaders(headBlock);
  const ct = parseParams(headers.get("content-type") ?? "text/plain");
  const disp = parseParams(headers.get("content-disposition") ?? "");
  const filename = disp.params.filename ?? ct.params.name;
  const part: EmailPart = { contentType: ct.type || "text/plain", params: ct.params, headers, filename, bytes: Buffer.byteLength(body), parts: [] };
  if (part.contentType.startsWith("multipart/") && ct.params.boundary && depth < MAX_DEPTH) {
    const b = ct.params.boundary;
    const pieces = body.split(new RegExp(`(?:^|\\n)--${b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:--)?[ \\t]*(?:\\n|$)`));
    for (const piece of pieces.slice(1)) {
      if (!piece.trim() || budget.n++ > MAX_PARTS) continue;
      part.parts.push(parsePart(piece.replace(/^\n+/, ""), depth + 1, budget));
    }
    return part;
  }
  if (TEXTLIKE.test(part.contentType)) {
    const d = decodeBody(body, headers.get("content-transfer-encoding") ?? "", (ct.params.charset ?? "").toLowerCase());
    part.text = d.text; part.bytes = d.bytes;
  }
  return part;
}

/** Parse a raw message (headers, blank line, body). Tolerant of bare LF and of missing MIME headers. */
export function parseEmail(raw: string): EmailPart {
  return parsePart(raw.replace(/\r\n?/g, "\n").replace(/^\s*\n/, ""), 0, { n: 0 });
}

const leaves = (p: EmailPart): EmailPart[] => (p.parts.length ? p.parts.flatMap(leaves) : [p]);

// ---------- sender ----------

interface Address { name: string; address: string; domain: string }
function parseAddress(v: string | undefined): Address | undefined {
  if (!v) return undefined;
  const m = v.match(/^\s*(?:"?([^"<]*?)"?\s*)?<([^<>\s]+@[^<>\s]+)>\s*$/) ?? v.match(/^\s*()([^\s<>@]+@[^\s<>]+)\s*$/);
  if (!m) return undefined;
  const address = m[2].toLowerCase();
  return { name: (m[1] ?? "").trim(), address, domain: address.split("@")[1] ?? "" };
}
/** the part of a host a person recognises: example.co.uk, example.com */
const site = (domain: string) => { const p = domain.split("."); const tld2 = /^(co|com|org|net|gov|ac|edu)$/.test(p[p.length - 2] ?? "") && (p[p.length - 1] ?? "").length === 2; return p.slice(tld2 ? -3 : -2).join("."); };
const FREEMAIL = /^(gmail|googlemail|outlook|hotmail|live|yahoo|ymail|aol|icloud|me|proton|protonmail|pm|gmx|mail|yandex|zoho|qq|163|126)\.[a-z.]+$/;
const AUTHORITY_NAME = /\b(security|support|help ?desk|it (team|department|admin)|administrator|admin|billing|accounts? (team|payable)|payroll|human resources|hr (team|department)|compliance|legal|ceo|cfo|system|no-?reply|postmaster|microsoft|google|apple|amazon|paypal|anthropic|openai|github|bank)\b/i;

function senderFindings(h: Map<string, string>): Finding[] {
  const out: Finding[] = [];
  const from = parseAddress(h.get("from"));
  if (!from) return out;
  const replyTo = parseAddress((h.get("reply-to") ?? "").split(",")[0]);
  // A mailing list or a newsletter service sets Reply-To on purpose and says what it is (List-Id,
  // List-Unsubscribe, Precedence: bulk). There the mismatch is how the list works, and it is not reported.
  const declaredList = h.has("list-id") || h.has("list-unsubscribe") || h.has("list-post") || /\b(bulk|list)\b/i.test(h.get("precedence") ?? "") || h.has("mailing-list") || h.has("x-mailing-list");
  if (replyTo && site(replyTo.domain) !== site(from.domain) && !declaredList) {
    // on its own this is weak: plenty of people answer from one address and read another
    out.push({ pass: "channel", kind: "email.sender_mismatch", confidence: 0.2, severity: 0.4, message: `replies go to ${replyTo.domain}, not to the sender's ${from.domain}`, excerpt: `From ${from.address}, Reply-To ${replyTo.address}`, location: "email/header:reply-to", action: "none" });
  }
  // a display name that is itself an address, at a different site than the real one
  const inName = from.name.match(/[^\s<>@"]+@([a-z0-9.-]+\.[a-z]{2,})/i);
  if (inName && site(inName[1].toLowerCase()) !== site(from.domain)) {
    out.push({ pass: "channel", kind: "email.sender_mismatch", confidence: 0.6, severity: 0.7, message: `the sender's display name shows an address at ${inName[1].toLowerCase()}, but the message is from ${from.domain}`, excerpt: `${from.name} <${from.address}>`, location: "email/header:from", action: "none" });
  } else if (from.name && AUTHORITY_NAME.test(from.name) && FREEMAIL.test(from.domain)) {
    out.push({ pass: "channel", kind: "email.sender_mismatch", confidence: 0.35, severity: 0.6, message: `the sender calls itself "${from.name.slice(0, 60)}" and writes from a free mail address (${from.domain})`, excerpt: `${from.name} <${from.address}>`, location: "email/header:from", action: "none" });
  }
  // what the receiving server concluded about where it really came from
  const auth = (h.get("authentication-results") ?? "").toLowerCase();
  const failed = ["dmarc", "spf", "dkim"].filter((k) => new RegExp(`\\b${k}=(fail|softfail|permerror)\\b`).test(auth));
  if (failed.includes("dmarc") || failed.length >= 2) {
    out.push({ pass: "channel", kind: "email.authentication_failed", confidence: 0.45, severity: 0.6, message: `the receiving server could not confirm the sender (${failed.join(", ")} failed)`, location: "email/header:authentication-results", action: "none" });
  }
  return out;
}

// ---------- adapter ----------

/** headers a mail client shows a person */
const SHOWN_HEADERS = ["subject", "from", "to", "cc", "reply-to", "date"];
/** headers that are routing and bookkeeping, not prose */
const BOOKKEEPING = /^(received|authentication-results|arc-|dkim-signature|domainkey-|x-google-|x-gm-|x-ms-|x-microsoft-|x-forefront-|x-originating-|x-received|message-id|in-reply-to|references|mime-version|content-|return-path|delivered-to|list-(unsubscribe|id|post|help|archive|subscribe|owner)|precedence|feedback-id|x-mailer|x-spam|x-virus|x-sg-|x-ses-|x-mc-|x-mailgun-|x-pm-|received-spf|errors-to|sender|thread-|importance|x-priority|priority|user-agent|x-report-abuse|x-campaign|x-csa-|bimi-|x-entity-ref-id|auto-submitted)/;

function adaptParsed(root: EmailPart, path: string, segments: TextSegment[], findings: Finding[], depth: number): void {
  const h = root.headers;
  for (const name of SHOWN_HEADERS) { const v = h.get(name); if (v) segments.push({ text: v, visibility: "visible", path: `${path}/header:${name}` }); }
  // any other header with prose in it: a tool reading raw headers sees it, a person never does
  for (const [name, v] of h) {
    if (SHOWN_HEADERS.includes(name) || BOOKKEEPING.test(name)) continue;
    if (v.trim().split(/\s+/).length >= 4) segments.push({ text: v, visibility: "attribute", path: `${path}/header:${name}` });
  }
  findings.push(...senderFindings(h));

  const all = leaves(root);
  const isAttachment = (p: EmailPart) => !!p.filename || /attachment/i.test(p.headers.get("content-disposition") ?? "");
  const htmlParts = all.filter((p) => p.contentType === "text/html" && !isAttachment(p) && p.text);
  const plainParts = all.filter((p) => p.contentType === "text/plain" && !isAttachment(p) && p.text);
  const html = htmlParts.map((p) => p.text!).join("\n");
  const plain = plainParts.map((p) => p.text!).join("\n");

  let remote: string[] = [];
  if (html.trim()) {
    const v = analyzeHtml(html);
    for (const s of v.segments) segments.push({ ...s, path: `${path}/html${s.path}` });
    findings.push(...v.findings.map((f) => ({ ...f, location: `${path}/html${f.location ?? ""}` })));
    remote = [...html.matchAll(/<(?:img|link|script|iframe|source|video|audio|embed|object|input)\b[^>]*?\b(?:src|href|data|background|poster)\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi), ...html.matchAll(/url\(\s*["']?(https?:\/\/[^"')\s]+)/gi)].map((m) => m[1]);
    if (plain.trim()) {
      // what the plain part says that the HTML part, hidden text included, does not say anywhere
      const only = passagesOnlyIn(plain, v.segments.map((s) => s.text).join(" "));
      if (only.length) {
        findings.push({ pass: "channel", kind: "email.part_divergence", confidence: 0.3, severity: 0.6, message: `the plain-text part says ${only.length} thing(s) the part a mail client shows does not`, excerpt: only[0].slice(0, 160), location: `${path}/text`, action: "none" });
        for (const [i, t] of only.entries()) segments.push({ text: t, visibility: "concealed", path: `${path}/text~plain-only[${i}]` });
      }
    }
  } else if (plain.trim()) {
    segments.push({ text: plain, visibility: "visible", path: `${path}/text` });
  }

  if (remote.length) {
    const hosts = [...new Set(remote.map((u) => { try { return new URL(u).hostname; } catch { return ""; } }).filter(Boolean))];
    // informational: Ingress did not load them, and says so
    findings.push({ pass: "channel", kind: "email.remote_content", confidence: 0, severity: 0, message: `${remote.length} remote resource(s) from ${hosts.length} host(s) were not loaded: ${hosts.slice(0, 6).join(", ")}`, location: `${path}/html`, action: "none" });
    // A remote address with a blank to fill in ("?d={{conversation}}") is a request waiting for data: whoever
    // renders the message, or an assistant asked to "show the image", completes it. An opaque token in a
    // tracking pixel is not that, and every newsletter has one.
    const templated = remote.find((u) => /[?&][^=&#]*=[^&#]*(?:\{\{|\$\{|%7B%7B|\{[a-z_ ]{3,}\}|\[(?:secret|key|token|context|conversation|summary|data|history|prompt|messages?)\])/i.test(u));
    if (templated) findings.push({ pass: "channel", kind: "meaning.exfil_link", confidence: 0.7, severity: 0.9, message: "a remote resource address in the message has a placeholder to be filled with data", excerpt: templated.slice(0, 120), location: `${path}/html`, action: "neutralized" });
  }

  const skipped: string[] = [];
  let n = 0;
  for (const p of all) {
    if (htmlParts.includes(p) || plainParts.includes(p)) continue;
    const label = p.filename ?? p.contentType;
    if (p.filename) segments.push({ text: p.filename, visibility: "visible", path: `${path}/attachment[${n}]@name` });
    if (p.text === undefined) { skipped.push(`${label} (${p.contentType}, ${p.bytes} bytes)`); n++; continue; }
    const at = `${path}/attachment[${n++}]`;
    if (/calendar|\bics\b/.test(p.contentType) || /\.ics$/i.test(p.filename ?? "")) {
      const c = adaptCalendar(p.text);
      for (const s of c.segments) segments.push({ ...s, path: `${at}/${s.path}` });
      findings.push(...c.findings);
    } else if (p.contentType === "message/rfc822" && depth < 4) {
      adaptParsed(parseEmail(p.text), `${at}/message`, segments, findings, depth + 1);
    } else if (p.contentType === "text/html" || /\.html?$/i.test(p.filename ?? "")) {
      const v = analyzeHtml(p.text);
      for (const s of v.segments) segments.push({ ...s, path: `${at}${s.path}` });
      findings.push(...v.findings);
    } else {
      // a text attachment is read when someone opens it: the reader sees all of it
      segments.push({ text: p.text, visibility: "visible", path: at });
    }
  }
  if (skipped.length) findings.push({ pass: "channel", kind: "email.uninspected_part", confidence: 0, severity: 0, message: `${skipped.length} attachment(s) could not be read as text and were not inspected: ${skipped.slice(0, 5).join("; ")}`, location: `${path}/attachments`, action: "none" });
}

type Json = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : "");
const b64url = (s: string) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");

/** Gmail API (users.messages.get, format=full) payload -> the same tree a raw message parses to. */
function fromGmailPayload(p: Json, depth = 0): EmailPart {
  const headers = new Map<string, string>();
  for (const h of Array.isArray(p.headers) ? p.headers : []) { if (h && typeof h === "object") { const n = str((h as Json).name).toLowerCase(); if (n) headers.set(n, headers.has(n) ? `${headers.get(n)}\n${str((h as Json).value)}` : str((h as Json).value)); } }
  const ct = parseParams(headers.get("content-type") ?? str(p.mimeType));
  const type = str(p.mimeType).toLowerCase() || ct.type || "text/plain";
  const body = (p.body ?? {}) as Json;
  const part: EmailPart = { contentType: type, params: ct.params, headers, filename: str(p.filename) || undefined, bytes: Number(body.size) || 0, parts: [] };
  if (Array.isArray(p.parts) && depth < MAX_DEPTH) part.parts = p.parts.filter((x): x is Json => !!x && typeof x === "object").slice(0, MAX_PARTS).map((x) => fromGmailPayload(x, depth + 1));
  else if (typeof body.data === "string" && TEXTLIKE.test(type)) part.text = b64url(body.data);
  return part;
}

/** A message as Microsoft Graph, or a simple mail tool, returns it -> the same tree. */
function fromFlatJson(m: Json): EmailPart {
  const headers = new Map<string, string>();
  const addr = (v: unknown): string => {
    if (typeof v === "string") return v;
    if (Array.isArray(v)) return v.map(addr).filter(Boolean).join(", ");
    if (v && typeof v === "object") { const e = ((v as Json).emailAddress ?? v) as Json; const a = str(e.address) || str(e.email); const n = str(e.name); return a ? (n ? `${n} <${a}>` : a) : n; }
    return "";
  };
  const set = (k: string, v: string) => { if (v) headers.set(k, v); };
  set("subject", str(m.subject)); set("from", addr(m.from ?? m.sender)); set("to", addr(m.toRecipients ?? m.to)); set("cc", addr(m.ccRecipients ?? m.cc));
  set("reply-to", addr(m.replyTo ?? m.reply_to ?? m["reply-to"])); set("date", str(m.receivedDateTime) || str(m.date));
  for (const h of Array.isArray(m.internetMessageHeaders) ? m.internetMessageHeaders : []) { if (h && typeof h === "object") { const n = str((h as Json).name).toLowerCase(); if (n && !headers.has(n)) headers.set(n, str((h as Json).value)); } }
  const body = m.body && typeof m.body === "object" ? (m.body as Json) : undefined;
  const htmlText = str(m.html) || str(m.bodyHtml) || str(m.htmlBody) || str(m.body_html) || (body && /html/i.test(str(body.contentType)) ? str(body.content) : "");
  const plainText = str(m.text) || str(m.plain) || str(m.bodyText) || str(m.textBody) || str(m.body_text) || (typeof m.body === "string" ? m.body : "") || (body && !/html/i.test(str(body.contentType)) ? str(body.content) : "") || str(m.bodyPreview) || str(m.snippet);
  const parts: EmailPart[] = [];
  const leaf = (contentType: string, text: string): EmailPart => ({ contentType, params: {}, headers: new Map(), text, bytes: Buffer.byteLength(text), parts: [] });
  if (plainText) parts.push(leaf("text/plain", plainText));
  if (htmlText) parts.push(leaf("text/html", htmlText));
  for (const a of Array.isArray(m.attachments) ? m.attachments : []) {
    if (!a || typeof a !== "object") continue;
    const A = a as Json;
    const type = (str(A.contentType) || str(A.mimeType) || "application/octet-stream").toLowerCase();
    const p: EmailPart = { contentType: type, params: {}, headers: new Map(), filename: str(A.name) || str(A.filename) || undefined, bytes: Number(A.size) || 0, parts: [] };
    const data = str(A.contentBytes) || str(A.data) || str(A.content);
    if (data && TEXTLIKE.test(type)) { try { p.text = str(A.content) ? str(A.content) : Buffer.from(data, "base64").toString("utf8"); } catch { /* not text after all */ } }
    parts.push(p);
  }
  return { contentType: "multipart/alternative", params: {}, headers, bytes: 0, parts };
}

/** Is this parsed JSON one email message, or a list of them? */
export function looksLikeEmailJson(doc: unknown): boolean {
  const one = (m: unknown): boolean => {
    if (!m || typeof m !== "object") return false;
    const o = m as Json;
    if (o.payload && typeof o.payload === "object" && Array.isArray((o.payload as Json).headers)) return true; // Gmail
    const hasSender = "from" in o || "sender" in o;
    const hasBody = "body" in o || "bodyPreview" in o || "snippet" in o || "text" in o || "html" in o || "textBody" in o || "htmlBody" in o;
    return "subject" in o && hasSender && hasBody;
  };
  if (Array.isArray(doc)) return doc.length > 0 && doc.every(one);
  if (doc && typeof doc === "object") { const d = doc as Json; for (const k of ["messages", "value", "items", "emails", "results"]) if (Array.isArray(d[k]) && (d[k] as unknown[]).length && (d[k] as unknown[]).every(one)) return true; }
  return one(doc);
}

export function adaptEmail(raw: string): EmailAdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const head = raw.slice(0, 2000).trimStart();
  if (head.startsWith("{") || head.startsWith("[")) {
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch { doc = undefined; }
    if (doc !== undefined) {
      const d = doc as Json;
      const list: unknown[] = Array.isArray(doc) ? doc : (["messages", "value", "items", "emails", "results"].map((k) => d?.[k]).find(Array.isArray) as unknown[] | undefined) ?? [doc];
      list.slice(0, 500).forEach((m, i) => {
        if (!m || typeof m !== "object") return;
        const o = m as Json;
        const root = o.payload && typeof o.payload === "object" ? fromGmailPayload(o.payload as Json) : fromFlatJson(o);
        adaptParsed(root, list.length > 1 ? `email[${i}]` : "email", segments, findings, 0);
        // a snippet is what an inbox list (and many tools) show before the message is opened
        if (o.payload && str(o.snippet)) segments.push({ text: str(o.snippet), visibility: "visible", path: `${list.length > 1 ? `email[${i}]` : "email"}/snippet` });
      });
      return { segments, findings };
    }
  }
  adaptParsed(parseEmail(raw), "email", segments, findings, 0);
  return { segments, findings };
}

/** Does this text look like a raw message: header lines first, with the headers every message has? */
export function looksLikeRawEmail(text: string): boolean {
  const head = text.slice(0, 8000).replace(/\r\n?/g, "\n");
  const block = head.split(/\n\n/)[0];
  if (!/^[A-Za-z][A-Za-z0-9-]*:[ \t]/.test(block)) return false;
  const names = new Set([...block.matchAll(/^([A-Za-z][A-Za-z0-9-]*):/gm)].map((m) => m[1].toLowerCase()));
  const core = ["from", "to", "subject", "date", "message-id", "received", "mime-version", "return-path", "delivered-to"].filter((n) => names.has(n)).length;
  return names.has("from") && core >= 3;
}
