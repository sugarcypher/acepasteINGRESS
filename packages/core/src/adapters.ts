/**
 * Content adapters: turn any supported content kind into the common shape
 * the passes consume (segments with visibility, scripts, decoded blobs).
 *
 * HTML goes through visibility.ts. Everything else comes through here.
 */

import type { ContentKind, Finding, TextSegment } from "./types.js";
import { adaptTerminal } from "./terminal.js";
import { adaptEmail, looksLikeEmailJson, looksLikeRawEmail } from "./email.js";
import { adaptCalendar, looksLikeCalendarJson } from "./calendar.js";
import { adaptMessages, adaptNotifications, looksLikeMessagesJson, looksLikeNotificationJson } from "./messages.js";
import { adaptCaptions, looksLikeCaptions, looksLikeTranscriptJson, type CaptionHints } from "./captions.js";
import { adaptNearby, looksLikeNearbyJson, type NearbyHints } from "./nearby.js";
import { adaptShortcut, looksLikeShortcut } from "./shortcuts.js";

/** JSON whose shape is a known channel (a mail message, a calendar event) is read as that channel */
function jsonChannel(body: string): ContentKind | undefined {
  let doc: unknown;
  try { doc = JSON.parse(body); } catch { return undefined; }
  if (looksLikeEmailJson(doc)) return "email";
  if (looksLikeCalendarJson(doc)) return "calendar";
  if (looksLikeMessagesJson(doc)) return "message";
  if (looksLikeNotificationJson(doc)) return "notification";
  if (looksLikeTranscriptJson(doc)) return "captions";
  if (looksLikeShortcut(doc)) return "automation";
  if (looksLikeNearbyJson(doc)) return "nearby";
  return "json";
}

export function detectKind(contentType: string, body: string, urlHint = ""): ContentKind {
  const ct = contentType.toLowerCase();
  if (/x-log|x-terminal|x-ansi/.test(ct) || /\.log(\?|#|$)/i.test(urlHint)) return "log";
  if (/message\/rfc822|message\/global/.test(ct) || /\.eml(\?|#|$)/i.test(urlHint)) return "email";
  if (/text\/calendar|application\/ics/.test(ct) || /\.ics(\?|#|$)/i.test(urlHint)) return "calendar";
  if (/text\/vtt|application\/x-subrip/.test(ct) || /\.(vtt|srt)(\?|#|$)/i.test(urlHint) || looksLikeCaptions(body)) return "captions";
  // terminal control sequences anywhere in the first part: replay it as a terminal would, whatever it claims to be
  if (/\x1b[\[\]]/.test(body.slice(0, 65_536)) && !/html|xhtml/.test(ct)) return "log";
  if (/html|xhtml/.test(ct)) return "html";
  if (/markdown/.test(ct) || /\.(md|markdown)(\?|#|$)/i.test(urlHint)) return "markdown";
  if (/json/.test(ct)) return jsonChannel(body) ?? "json";
  if (/javascript|ecmascript/.test(ct) || /\.(m?js|cjs)(\?|#|$)/i.test(urlHint)) return "javascript";
  const head = body.slice(0, 2048);
  if (/^\s*BEGIN:VCALENDAR\b/i.test(head)) return "calendar";
  // a shortcut saved as an XML property list
  if (/^\s*(?:<\?xml|<!DOCTYPE plist|<plist)/i.test(head) && /<key>WFWorkflowActions<\/key>/.test(body.slice(0, 200_000))) return "automation";
  if (looksLikeRawEmail(body)) return "email";
  if (/^\s*<(!doctype|html|head|body|div|p|span|article|main|table)/i.test(head)) return "html";
  if (/^\s*[\[{]/.test(head)) { const k = jsonChannel(body); if (k) return k; }
  if (/^(#{1,6}\s|\*\*|- |\d+\. |```|\[.+\]\(.+\))/m.test(head) && /\n/.test(head)) return "markdown";
  return "text";
}

/**
 * Decode numeric and the common named entities so entity-smuggled
 * characters (&#8203; &#x200B; &zwj;) reach the character pass as the
 * characters they are. Returns the decoded text and the count of
 * suspicious decodes (format controls, tags, selectors).
 */
export function decodeEntities(text: string): { text: string; suspicious: number; sample: string } {
  const named: Record<string, string> = {
    amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", zwj: "‍", zwnj: "‌", lrm: "‎", rlm: "‏", shy: "­",
    NoBreak: "⁠", ZeroWidthSpace: "​", NegativeMediumSpace: "​",
  };
  let suspicious = 0;
  let sample = "";
  const isSuspicious = (cp: number) =>
    (cp >= 0x200b && cp <= 0x200f) || cp === 0x2060 || cp === 0xfeff || cp === 0x00ad || (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069) || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0000 && cp <= 0xe007f) || (cp >= 0xe0100 && cp <= 0xe01ef);
  const out = text.replace(/&(#x[0-9a-fA-F]{1,6}|#\d{1,7}|[a-zA-Z]{2,20});/g, (m, body: string) => {
    let cp: number | undefined;
    if (body[0] === "#") cp = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
    else if (body in named) { const ch = named[body]; cp = ch.codePointAt(0); }
    if (cp === undefined || Number.isNaN(cp) || cp > 0x10ffff) return m;
    if (isSuspicious(cp)) { suspicious++; if (!sample) sample = m; }
    return String.fromCodePoint(cp);
  });
  return { text: out, suspicious, sample };
}

export interface AdapterResult {
  segments: TextSegment[];
  findings: Finding[];
}

/** Markdown: comments and non-rendered constructs are hidden; rendered text is visible. */
export function adaptMarkdown(raw: string): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  let text = raw;

  // HTML comments inside markdown render nothing
  text = text.replace(/<!--([\s\S]*?)-->/g, (_, c: string) => {
    if (c.trim()) segments.push({ text: c, visibility: "comment", path: "md/comment" });
    return " ";
  });
  // reference-style link definitions: [id]: url "title" — the title and url never render
  text = text.replace(/^\s{0,3}\[[^\]]+\]:\s*(\S+)(?:\s+["'(]([^"')]*)["')])?\s*$/gm, (_, url: string, title?: string) => {
    if (title?.trim()) segments.push({ text: title, visibility: "attribute", path: "md/linkdef@title" });
    if (/[?#].{40,}/.test(url)) segments.push({ text: url, visibility: "attribute", path: "md/linkdef@url" });
    return " ";
  });
  // inline link/image titles and urls
  text = text.replace(/!?\[([^\]]*)\]\(([^)\s]+)(?:\s+["']([^"']*)["'])?\)/g, (m, label: string, url: string, title?: string) => {
    if (title?.trim()) segments.push({ text: title, visibility: "attribute", path: "md/link@title" });
    // an image's alt text does not render where the image does: read it as the alt attribute it becomes
    if (m.startsWith("!") && label.trim().split(/\s+/).length >= 4) segments.push({ text: label, visibility: "attribute", path: "md/image@alt" });
    // keep the construct for the meaning pass (markdown image exfil) by leaving it in visible text
    return m;
  });
  // raw HTML blocks inside markdown: hidden attributes and styles
  text = text.replace(/<([a-z][\w-]*)([^>]*)>/gi, (m, _tag: string, attrs: string) => {
    if (/display\s*:\s*none|visibility\s*:\s*hidden|hidden(\s|=|>|$)|aria-hidden\s*=\s*["']?true|font-size\s*:\s*0|opacity\s*:\s*0/i.test(attrs)) {
      segments.push({ text: m, visibility: "css_hidden", path: "md/html-open-tag" });
      findings.push({ pass: "visibility", kind: "visibility.markdown_hidden", confidence: 0.6, severity: 0.6, message: "raw HTML with hiding styles inside markdown", excerpt: m.slice(0, 120), location: "md/html", action: "none" });
    }
    const alt = attrs.match(/\b(alt|title|aria-label)\s*=\s*["']([^"']{20,})["']/i);
    if (alt) segments.push({ text: alt[2], visibility: "attribute", path: `md/html@${alt[1]}` });
    return " ";
  });
  // fenced code is visible but is code; keep it visible (the model reads it)
  segments.unshift({ text, visibility: "visible", path: "md" });

  for (const s of segments) {
    if (s.visibility === "visible") continue;
    const words = s.text.trim().split(/\s+/).length;
    if (words < 6) continue;
    findings.push({
      pass: "visibility", kind: "visibility.markdown_hidden", confidence: Math.min(0.9, 0.5 + words / 100), severity: 0.6,
      message: `${words} words in a markdown construct that does not render (${s.path})`, excerpt: s.text.trim().slice(0, 160), location: s.path, action: "none",
    });
  }
  return { segments, findings };
}

/** JSON: every string value is a segment; keys hint at intent. Nothing is "hidden" in JSON, but long strings in unusual keys are attribute-like. */
export function adaptJson(raw: string): AdapterResult {
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { return adaptText(raw); }
  const walk = (v: unknown, path: string, depth: number) => {
    if (depth > 64) return;
    if (typeof v === "string") {
      const keyPath = path.replace(/^\$/, "");
      if (v.trim()) segments.push({ text: v, visibility: /(\.|\[)(_|__|\$|meta|hidden|internal|debug|comment|instruction|instructions|prompt|system)(\b|\.|\[|$)/i.test(keyPath) ? "attribute" : "visible", path });
    } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`, depth + 1));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`, depth + 1);
  };
  walk(doc, "$", 0);
  for (const s of segments) {
    if (s.visibility !== "attribute") continue;
    const words = s.text.trim().split(/\s+/).length;
    if (words >= 6) findings.push({ pass: "visibility", kind: "visibility.attribute_only", confidence: 0.4, severity: 0.5, message: `${words} words under a metadata-like JSON key`, excerpt: s.text.slice(0, 160), location: s.path, action: "none" });
  }
  return { segments, findings };
}

export function adaptText(raw: string): AdapterResult {
  return { segments: [{ text: raw, visibility: "visible", path: "text" }], findings: [] };
}

/**
 * One adapter per content kind. HTML is not here: it goes through visibility.ts, which needs the stylesheet
 * rules the engine fetched. A kind without an adapter yet is read as plain text, so nothing is skipped.
 */
export function adaptByKind(kind: ContentKind, raw: string, hints: CaptionHints & NearbyHints = {}): AdapterResult {
  switch (kind) {
    case "captions": return adaptCaptions(raw, hints);
    case "markdown": return adaptMarkdown(raw);
    case "json": return adaptJson(raw);
    case "javascript": return adaptJavascript(raw);
    case "log": return adaptTerminal(raw);
    case "email": return adaptEmail(raw);
    case "calendar": return adaptCalendar(raw);
    case "message": return adaptMessages(raw);
    case "notification": return adaptNotifications(raw);
    case "nearby": return adaptNearby(raw, hints);
    case "automation": return adaptShortcut(raw);
    default: return adaptText(raw);
  }
}

/** kinds whose adapters parse HTML themselves: entities in them must reach that parser undecoded */
export const KINDS_WITH_MARKUP: ReadonlySet<ContentKind> = new Set<ContentKind>(["html", "email", "calendar", "message", "notification", "captions", "nearby", "automation"]);

/** Plain JavaScript fetched directly (a module, a bundle): the whole thing is a script; any string literals are visible text. */
export function adaptJavascript(raw: string): AdapterResult {
  const strings = raw.match(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g) ?? [];
  const text = strings.map((s) => s.slice(1, -1)).join("\n");
  return { segments: [{ text, visibility: "visible", path: "js/strings" }], findings: [] };
}
