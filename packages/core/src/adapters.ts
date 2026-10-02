/**
 * Content adapters: turn any supported content kind into the common shape
 * the passes consume (segments with visibility, scripts, decoded blobs).
 *
 * HTML goes through visibility.ts. Everything else comes through here.
 */

import type { ContentKind, Finding, TextSegment } from "./types.js";

export function detectKind(contentType: string, body: string, urlHint = ""): ContentKind {
  const ct = contentType.toLowerCase();
  if (/html|xhtml/.test(ct)) return "html";
  if (/markdown/.test(ct) || /\.(md|markdown)(\?|#|$)/i.test(urlHint)) return "markdown";
  if (/json/.test(ct)) return "json";
  if (/javascript|ecmascript/.test(ct) || /\.(m?js|cjs)(\?|#|$)/i.test(urlHint)) return "javascript";
  const head = body.slice(0, 2048);
  if (/^\s*<(!doctype|html|head|body|div|p|span|article|main|table)/i.test(head)) return "html";
  if (/^\s*[\[{]/.test(head)) { try { JSON.parse(body); return "json"; } catch { /* not json */ } }
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

/** Plain JavaScript fetched directly (a module, a bundle): the whole thing is a script; any string literals are visible text. */
export function adaptJavascript(raw: string): AdapterResult {
  const strings = raw.match(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g) ?? [];
  const text = strings.map((s) => s.slice(1, -1)).join("\n");
  return { segments: [{ text, visibility: "visible", path: "js/strings" }], findings: [] };
}
