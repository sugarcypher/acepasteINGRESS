/**
 * ingress show: "what your agent sees".
 *
 * Draws one page two ways, side by side: what a person sees (the text the visibility pass models as rendered)
 * and what an AI agent receives (every piece of text in the source). Each piece a person would not see is
 * highlighted in place and labelled by how it is hidden. The verdict, findings, cloaking comparison and receipt
 * come from the ordinary engine run; this module only draws them.
 *
 * Nothing here contacts the network. The page is fetched by the engine's normal fetch (IngressEngine.fetch), and
 * the report is one static HTML file: inline CSS, a strict Content-Security-Policy, no scripts, no fonts, no
 * remote images. Every byte that came from the page is escaped before it is written, so the report cannot be
 * used to run the page's own markup.
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { IngressEngine, type EngineDeps, type IngressOptions } from "./engine.js";
import { analyzeHtml } from "./visibility.js";
import { adaptByKind, detectKind } from "./adapters.js";
import { servedWords, passagesOnlyIn } from "./served.js";
import { ACEPASTE_INVISIBLE_SOURCE, ACEPASTE_INVISIBLE_SUPPL_SOURCE } from "./acepaste-alphabet.js";
import type { AcquireResult, ContentKind, Finding, IngressConfig, IngressResult, TextSegment, Tier } from "./types.js";

/** How a piece of text is kept from a person. "unicode" is a run of invisible or control characters. */
export type ShowKind = "css" | "color" | "unicode" | "markup" | "cloaked";

export const SHOW_KIND_LABEL: Record<ShowKind, string> = {
  css: "hidden by CSS",
  color: "colour matches background, or too small to read",
  unicode: "invisible Unicode",
  markup: "comment, attribute, srcdoc or SVG",
  cloaked: "served only to AI fetchers",
};

/** One run of text in the agent's copy. `kind` is absent for text a person sees. */
export interface ShowPiece {
  text: string;
  kind?: ShowKind;
  /** finer label: "comment", "alt", "srcdoc", "offscreen", "U+200B" */
  detail?: string;
  /** anchor id of a highlight, h1, h2, ... */
  id?: string;
}

/** One segment of the source, split into runs. `block` starts a new line in the drawing. */
export interface ShowSegment { pieces: ShowPiece[]; block: boolean; path: string }

export interface ShowFinding { kind: string; message: string; severity: number; confidence: number; excerpt?: string; target?: string }

export interface ShowModel {
  source: string;
  finalUrl?: string;
  contentKind: ContentKind;
  tier: Tier;
  score: number;
  /** what a person sees: the browser copy when one was compared, else the judged copy's visible text */
  personSegments: ShowSegment[];
  /** what the agent receives: every segment of the judged copy, hidden ones highlighted */
  agentSegments: ShowSegment[];
  findings: ShowFinding[];
  counts: Record<ShowKind, number>;
  cloaking?: { compared: boolean; agentOnly: string[]; browserOnly: string[]; agentWords: number; browserWords: number };
  receipt?: { digest: string; rawDigest: string; issuedAt: string; engineVersion: string; rulesetVersion: string; signatureAlg?: string; keyId?: string; signed: boolean };
  note?: string;
}

const INVISIBLE_RUN = new RegExp(`(?:${ACEPASTE_INVISIBLE_SOURCE}|${ACEPASTE_INVISIBLE_SUPPL_SOURCE}|[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F\\u2028\\u2029])+`, "gu");
const TAG_CHAR = /^[\u{E0000}-\u{E007F}]$/u;
const BLOCK_TAGS = new Set(["p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "div", "section", "article", "header", "footer", "main", "nav", "aside", "blockquote", "pre", "td", "th", "tr", "dt", "dd", "figcaption", "summary", "title", "body", "html", "form", "label", "table", "ul", "ol"]);

const cp = (c: string) => "U+" + c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");

/** A run of invisible characters, named so a person can read it: ⟨U+200B⟩, or for tag characters what they spell. */
export function describeInvisible(run: string): string {
  const chars = [...run];
  if (chars.every((c) => TAG_CHAR.test(c))) {
    const spelled = chars.map((c) => { const v = c.codePointAt(0)! - 0xe0000; return v >= 0x20 && v < 0x7f ? String.fromCharCode(v) : ""; }).join("");
    return `tag characters ×${chars.length}${spelled ? `: "${spelled}"` : ""}`;
  }
  const names: string[] = [];
  for (let i = 0; i < chars.length;) {
    let j = i; while (j < chars.length && chars[j] === chars[i]) j++;
    names.push(j - i > 1 ? `${cp(chars[i])}×${j - i}` : cp(chars[i]));
    i = j;
  }
  return names.join(" ");
}

/** Split text into visible runs and invisible-character runs. */
function splitInvisible(text: string, kind: ShowKind | undefined, detail: string | undefined): ShowPiece[] {
  const out: ShowPiece[] = [];
  let last = 0;
  for (const m of text.matchAll(INVISIBLE_RUN)) {
    if (m.index! > last) out.push({ text: text.slice(last, m.index), kind, detail });
    out.push({ text: m[0], kind: "unicode", detail: describeInvisible(m[0]) });
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last), kind, detail });
  return out;
}

/** which invisible-character badge a character finding is about */
const UNICODE_FINDING_MATCH: Partial<Record<string, RegExp>> = {
  "unicode.tag_characters": /^tag characters/,
  "unicode.bidi_control": /U\+(?:202[A-E]|206[6-9]|200[EF]|061C)/,
  "unicode.zero_width": /U\+(?:200[B-D]|2060|FEFF|00AD|180E)/,
  "unicode.variation_selector_smuggling": /U\+(?:FE0[0-9A-F]|E01[0-9A-F]{2})/,
};

const lastTag = (path: string) => (path.split("/").pop() ?? "").replace(/[~@#].*$/, "");

/** How the visibility pass's label maps to a highlight kind. */
function kindOf(s: TextSegment): { kind?: ShowKind; detail?: string } {
  switch (s.visibility) {
    case "visible": return {};
    case "css_hidden": return s.path.includes("@srcdoc") ? { kind: "markup", detail: "iframe srcdoc" } : { kind: "css", detail: "CSS-hidden" };
    case "offscreen": return { kind: "css", detail: "off-screen" };
    case "tiny_or_transparent": return { kind: "color", detail: "colour match / tiny" };
    case "comment": return { kind: "markup", detail: "HTML comment" };
    case "attribute": {
      if (s.path.includes("@svg")) return { kind: "markup", detail: "SVG text" };
      const at = s.path.match(/@([^/]+)$/)?.[1];
      return { kind: "markup", detail: at ? `attribute ${at}` : lastTag(s.path) === "title" ? "page title" : "attribute" };
    }
    case "concealed": return { kind: "css", detail: "concealed" };
  }
}

function segmentsOf(raw: string, kind: ContentKind): TextSegment[] {
  if (kind === "html") return analyzeHtml(raw).segments;
  try { return adaptByKind(kind, raw).segments; } catch { return [{ text: raw, visibility: "visible", path: "" }]; }
}

const WS = /\s+/g;

/**
 * Build the drawing from an engine result and the raw copy it judged. `browserRaw` is the copy the
 * browser-fingerprint fetch received, when the cloaking compare ran.
 */
export function buildShowModel(input: { source: string; raw: string; result: IngressResult; browserRaw?: string; browserContentType?: string; note?: string }): ShowModel {
  const { result } = input;
  const kind = result.contentKind;
  const agentSegs = segmentsOf(input.raw, kind);
  const browserKind = input.browserRaw !== undefined ? detectKind(input.browserContentType ?? "", input.browserRaw, input.source) : undefined;
  const browserSegs = input.browserRaw !== undefined ? segmentsOf(input.browserRaw, browserKind!) : undefined;
  const browserWords = browserSegs ? new Set(servedWords(browserSegs.map((s) => s.text).join(" "))) : undefined;

  const counts: Record<ShowKind, number> = { css: 0, color: 0, unicode: 0, markup: 0, cloaked: 0 };
  let n = 0;
  const agentSegments: ShowSegment[] = [];
  for (const s of agentSegs) {
    let { kind: k, detail } = kindOf(s);
    // visible text the browser copy does not carry: words served only to the AI fetcher
    if (!k && browserWords) {
      const w = servedWords(s.text);
      const missing = w.filter((x) => !browserWords.has(x)).length;
      if (w.length && missing >= 3 && missing / w.length >= 0.6) { k = "cloaked"; detail = "agent-only"; }
    }
    const text = k ? s.text.replace(WS, " ").trim() : s.text.replace(WS, " ");
    if (!text.trim()) continue;
    const pieces = splitInvisible(text, k, detail);
    for (const p of pieces) if (p.kind) { p.id = `h${++n}`; counts[p.kind]++; }
    agentSegments.push({ pieces, block: !!k && k !== "unicode" ? true : BLOCK_TAGS.has(lastTag(s.path)), path: s.path });
  }

  const personSource = browserSegs ?? agentSegs;
  const personSegments: ShowSegment[] = personSource
    .filter((s) => s.visibility === "visible")
    .map((s) => ({ pieces: [{ text: s.text.replace(INVISIBLE_RUN, "").replace(WS, " ") }], block: BLOCK_TAGS.has(lastTag(s.path)), path: s.path }))
    .filter((s) => s.pieces[0].text.trim());

  // link each finding to the highlight it is about
  const highlights = agentSegments.flatMap((s) => s.pieces.map((p) => ({ p, path: s.path }))).filter((x) => x.p.id);
  const norm = (t: string) => t.replace(INVISIBLE_RUN, "").replace(WS, " ").trim().toLowerCase();
  const targetFor = (f: Finding): string | undefined => {
    if (f.kind.startsWith("cloaking.")) return highlights.find((x) => x.p.kind === "cloaked")?.p.id ?? (input.browserRaw !== undefined ? "cloaking" : undefined);
    if (f.pass === "character" || f.kind.startsWith("unicode.")) {
      const want = UNICODE_FINDING_MATCH[f.kind];
      const uni = highlights.filter((x) => x.p.kind === "unicode");
      return (want ? uni.find((x) => want.test(x.p.detail ?? "")) : undefined)?.p.id ?? uni[0]?.p.id;
    }
    if (f.location) { const h = highlights.find((x) => x.path === f.location && x.p.kind !== "unicode"); if (h) return h.p.id; }
    const ex = f.excerpt ? norm(f.excerpt).slice(0, 40) : "";
    if (ex.length >= 8) { const h = highlights.find((x) => x.p.kind !== "unicode" && norm(x.p.text).includes(ex)); if (h) return h.p.id; }
    if (f.inHidden) return highlights.find((x) => x.p.kind && x.p.kind !== "unicode")?.p.id;
    return undefined;
  };
  const findings: ShowFinding[] = result.findings
    .filter((f) => f.confidence * f.severity > 0 || f.pass !== "acquire")
    .sort((a, b) => b.confidence * b.severity - a.confidence * a.severity)
    .map((f) => ({ kind: f.kind, message: f.message, severity: f.severity, confidence: f.confidence, excerpt: f.excerpt, target: targetFor(f) }));
  // notes about the fetch itself (refused AI agent, incomplete comparison) travel with the report as plain notes
  const notes = result.findings.filter((f) => f.pass === "acquire" && f.confidence * f.severity === 0).map((f) => f.message);

  let cloaking: ShowModel["cloaking"];
  if (browserSegs) {
    const agentAll = agentSegs.filter((s) => s.visibility === "visible").map((s) => s.text.replace(WS, " ")).join("\n\n");
    const browserAll = browserSegs.map((s) => s.text.replace(WS, " ")).join("\n\n");
    cloaking = {
      compared: result.receipt.passesRun.includes("cloaking"),
      agentOnly: passagesOnlyIn(agentAll, browserAll, 5).slice(0, 40),
      browserOnly: passagesOnlyIn(browserSegs.filter((s) => s.visibility === "visible").map((s) => s.text.replace(WS, " ")).join("\n\n"), agentSegs.map((s) => s.text).join(" "), 5).slice(0, 40),
      agentWords: servedWords(agentAll).length,
      browserWords: servedWords(browserAll).length,
    };
  }

  const r = result.receipt;
  return {
    source: input.source,
    finalUrl: r.finalUrl && r.finalUrl !== r.url ? r.finalUrl : undefined,
    contentKind: kind,
    tier: result.tier,
    score: result.score,
    personSegments, agentSegments, findings, counts, cloaking,
    receipt: r.digest ? { digest: r.digest, rawDigest: r.rawDigest, issuedAt: r.issuedAt, engineVersion: r.engineVersion, rulesetVersion: r.rulesetVersion, signatureAlg: r.signatureAlg, keyId: r.keyId, signed: !!r.signature } : undefined,
    note: [input.note, ...notes].filter(Boolean).join(" ") || undefined,
  };
}

// ---------- gathering ----------

export interface ShowInput { url?: string; file?: string; /** passed to the fetch, e.g. a quarantine check */ fetchOptions?: IngressOptions }

/** Run the engine on a URL (its normal two-fingerprint fetch) or a local file, and build the drawing. */
export async function show(input: ShowInput, config: Partial<IngressConfig> = {}, deps: Pick<EngineDeps, "fetchImpl" | "resolver" | "sleep" | "random"> = {}): Promise<ShowModel> {
  if (input.url) {
    let copies: { judged: AcquireResult; browser?: AcquireResult } | undefined;
    const engine = new IngressEngine({ ...config, cacheTtlSeconds: 0 }, { ...deps, log: () => {}, onAcquired: (c) => { copies = c; } });
    const result = await engine.fetch(input.url, input.fetchOptions);
    if (!copies) return buildShowModel({ source: input.url, raw: "", result, note: "Nothing was read from this address, so there is nothing to draw." });
    // the browser copy is only a fair picture of "what a person sees" when the comparison actually ran
    const browser = copies.browser && copies.browser.status < 400 ? copies.browser : undefined;
    return buildShowModel({ source: input.url, raw: copies.judged.body, result, browserRaw: browser?.body, browserContentType: browser?.contentType,
      note: copies.judged.fingerprint === "human" ? "The AI fetcher was refused; this is the copy a browser-fingerprint fetch received." : undefined });
  }
  if (input.file) {
    const raw = readFileSync(input.file, "utf8");
    const engine = new IngressEngine({ ...config, cacheTtlSeconds: 0 }, { log: () => {} });
    const isHtml = /\.(html?|xhtml|svg)$/i.test(input.file) ? true : undefined;
    const result = await engine.scan(raw, { url: `file:${basename(input.file)}`, isHtml });
    return buildShowModel({ source: input.file, raw, result });
  }
  throw new Error("show needs a URL or a file");
}

// ---------- HTML report ----------

/** Escape text for HTML element content and attribute values. Control characters never reach the report raw. */
export function escapeHtml(s: string): string {
  return s
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, (c) => `⟨${cp(c)}⟩`)
    .replace(/[&<>"'`]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]!);
}
/** For one-line labels (a URL, a message): also neutralise bidi and other invisible characters so they cannot reorder the report. */
const escLine = (s: string) => escapeHtml(s.replace(INVISIBLE_RUN, (m) => `⟨${describeInvisible(m)}⟩`));

export const SHOW_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";

const TIER_WORDS: Record<Tier, string> = {
  clean: "Clean: nothing hidden that tries to steer an agent was found.",
  suspect: "Suspect: refused by default. A person may choose to let it through.",
  hostile: "Hostile: refused. This page carries content aimed at AI agents.",
  unreachable: "Unreachable: nothing could be read, so there is no verdict on the page.",
};

function drawSegments(segs: ShowSegment[]): string {
  if (!segs.length) return `<p class="empty">(no text)</p>`;
  const out: string[] = [];
  let line: string[] = [];
  const flush = () => { if (line.length) out.push(`<div class="ln">${line.join("")}</div>`); line = []; };
  for (const s of segs) {
    if (s.block) flush();
    for (const p of s.pieces) {
      if (!p.kind) { line.push(escapeHtml(p.text)); continue; }
      if (p.kind === "unicode") line.push(`<span class="u" id="${p.id}" title="${escLine(p.detail ?? "")}">⟨${escLine(p.detail ?? "")}⟩</span>`);
      else line.push(`<mark class="k-${p.kind}" id="${p.id}"><span class="tag">${escLine(p.detail ?? p.kind)}</span>${escapeHtml(p.text)}</mark>`);
    }
    if (s.block) flush();
  }
  flush();
  return out.join("\n");
}

export function renderShowHtml(m: ShowModel): string {
  const total = Object.values(m.counts).reduce((a, b) => a + b, 0);
  const legend = (Object.keys(SHOW_KIND_LABEL) as ShowKind[])
    .map((k) => `<li><span class="sw k-${k}"></span>${escapeHtml(SHOW_KIND_LABEL[k])} <b>${m.counts[k]}</b></li>`).join("");
  const findings = m.findings.length
    ? `<ol class="findings">${m.findings.map((f) => `<li class="${f.confidence * f.severity >= 0.3 ? "hi" : ""}">${f.target ? `<a href="#${f.target}">` : ""}${escLine(f.message)}${f.target ? "</a>" : ""} <code>${escapeHtml(f.kind)}</code>${f.excerpt ? `<div class="ex">${escLine(f.excerpt.slice(0, 240))}</div>` : ""}</li>`).join("")}</ol>`
    : `<p class="empty">No findings.</p>`;
  const cloak = m.cloaking ? `<section id="cloaking"><h2>Bots versus browsers</h2>
<p>The page was fetched twice: once as an AI assistant's fetcher, once as a desktop browser. ${m.cloaking.compared ? "The two copies were compared." : "The comparison could not be completed."} AI copy: ${m.cloaking.agentWords} words. Browser copy: ${m.cloaking.browserWords} words.</p>
<div class="cols"><div><h3>Only the AI fetcher got</h3>${m.cloaking.agentOnly.length ? `<ul class="diff add">${m.cloaking.agentOnly.map((p) => `<li>${escLine(p)}</li>`).join("")}</ul>` : `<p class="empty">Nothing beyond what the browser got.</p>`}</div>
<div><h3>Only the browser got</h3>${m.cloaking.browserOnly.length ? `<ul class="diff del">${m.cloaking.browserOnly.map((p) => `<li>${escLine(p)}</li>`).join("")}</ul>` : `<p class="empty">Nothing beyond what the AI fetcher got.</p>`}</div></div></section>` : "";
  const rc = m.receipt ? `<section><h2>Receipt</h2><dl class="rc"><dt>Receipt digest</dt><dd><code>${escapeHtml(m.receipt.digest)}</code></dd><dt>Content digest</dt><dd><code>${escapeHtml(m.receipt.rawDigest)}</code></dd><dt>Signed</dt><dd>${m.receipt.signed ? `yes, ${escapeHtml(m.receipt.signatureAlg ?? "")}${m.receipt.keyId ? ` (key ${escapeHtml(m.receipt.keyId)})` : ""}` : "no (no signing key configured)"}</dd><dt>Issued</dt><dd>${escapeHtml(m.receipt.issuedAt)}</dd><dt>Engine</dt><dd>${escapeHtml(m.receipt.engineVersion)}, ruleset ${escapeHtml(m.receipt.rulesetVersion)}</dd></dl></section>` : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${SHOW_CSP}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>What your agent sees: ${escLine(m.source.slice(0, 120))}</title>
<style>
:root{--fg:#1d1d1f;--mut:#6b6b70;--bg:#fbfbfa;--card:#fff;--line:#e4e4e0}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:1200px;margin:0 auto;padding:24px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}h3{font-size:14px;margin:0 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.src{color:var(--mut);word-break:break-all;margin:0 0 16px}
.banner{border-radius:10px;padding:14px 18px;font-weight:600;display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
.banner .score{font-weight:400;opacity:.85}.t-clean{background:#e6f4ea;color:#14532d}.t-suspect{background:#fff4d6;color:#713f12}.t-hostile{background:#fde2e1;color:#7f1d1d}.t-unreachable{background:#ececec;color:#333}
.legend{list-style:none;padding:0;margin:14px 0 0;display:flex;flex-wrap:wrap;gap:8px 18px;font-size:13px;color:var(--mut)}.legend b{color:var(--fg)}
.sw{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.cols{grid-template-columns:1fr}}
.pane{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;min-width:0;overflow-wrap:anywhere}
.ln{margin:0 0 8px;white-space:pre-wrap}.empty{color:var(--mut);font-style:italic}
mark{border-radius:4px;padding:1px 3px;color:inherit;white-space:pre-wrap}mark .tag{font-size:11px;font-weight:600;margin-right:6px;padding:0 4px;border-radius:3px;background:rgba(0,0,0,.12);user-select:none}
.k-css,.sw.k-css{background:#ffd7d5}.k-color,.sw.k-color{background:#ffe7b3}.k-unicode,.sw.k-unicode{background:#d9c8ff}.k-markup,.sw.k-markup{background:#cfe8ff}.k-cloaked,.sw.k-cloaked{background:#ffc2e5}
.u{display:inline-block;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;background:#d9c8ff;border-radius:4px;padding:0 4px;margin:0 1px;color:#3b0764}
:target{outline:3px solid #2563eb;outline-offset:2px}
.findings{padding-left:22px}.findings li{margin:0 0 10px}.findings li.hi{font-weight:600}.findings code{font-size:12px;color:var(--mut);font-weight:400}
.findings a{color:#1d4ed8}.ex{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut);font-weight:400;white-space:pre-wrap;margin-top:2px}
.diff{padding-left:18px}.diff li{margin:0 0 8px;padding:4px 8px;border-radius:6px}.add li{background:#ffc2e5}.del li{background:#e6f4ea}
.rc{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}.rc dt{color:var(--mut)}.rc dd{margin:0;word-break:break-all}
.note{color:var(--mut)}footer{margin-top:32px;color:var(--mut);font-size:12px}
</style></head><body><main>
<h1>What your agent sees</h1>
<p class="src">${escLine(m.source)}${m.finalUrl ? ` → ${escLine(m.finalUrl)}` : ""} · ${escapeHtml(m.contentKind)}</p>
<div class="banner t-${m.tier}"><span>${escapeHtml(m.tier.toUpperCase())}</span><span class="score">score ${m.score.toFixed(2)}</span><span class="score">${escapeHtml(TIER_WORDS[m.tier])}</span></div>
${m.note ? `<p class="note">${escLine(m.note)}</p>` : ""}
<ul class="legend">${legend}<li>${total} highlighted in all</li></ul>
<h2>Side by side</h2>
<div class="cols"><section class="pane"><h3>What a person sees</h3>${drawSegments(m.personSegments)}</section>
<section class="pane"><h3>What your AI agent receives</h3>${drawSegments(m.agentSegments)}</section></div>
<h2>Findings</h2>${findings}
${cloak}
${rc}
<footer>Made by AcePaste Ingress <code>ingress show</code>. A static report: no scripts, no remote content. Text from the page is shown as text, never run. "What a person sees" follows the engine's static model of the page (inline styles, the page's own &lt;style&gt; blocks, colours); styles set by scripts or linked stylesheets are not drawn here, though the verdict counts them.</footer>
</main></body></html>
`;
}

// ---------- terminal ----------

/** Visible text with every hidden span in red brackets. Page control characters are always shown as escapes, never sent to the terminal. */
export function renderShowTerm(m: ShowModel, opts: { color?: boolean } = {}): string {
  const red = (s: string) => (opts.color ? `\x1b[31m${s}\x1b[0m` : s);
  const dim = (s: string) => (opts.color ? `\x1b[2m${s}\x1b[0m` : s);
  const clean = (s: string) => s.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, (c) => `⟨${cp(c)}⟩`);
  const lines: string[] = [];
  let line = "";
  const flush = () => { if (line.trim()) lines.push(line.trim()); line = ""; };
  for (const s of m.agentSegments) {
    if (s.block) flush();
    for (const p of s.pieces) {
      if (!p.kind) line += clean(p.text);
      else if (p.kind === "unicode") line += red(`⟨${clean(p.detail ?? "")}⟩`);
      else line += red(`[${clean(p.detail ?? p.kind)}: ${clean(p.text)}]`);
    }
    if (s.block) flush();
  }
  flush();
  const total = Object.values(m.counts).reduce((a, b) => a + b, 0);
  const head = `${m.tier.toUpperCase()} (score ${m.score.toFixed(2)})  ${clean(m.source)}`;
  const tail = [`${total} hidden span(s): ${(Object.keys(m.counts) as ShowKind[]).filter((k) => m.counts[k]).map((k) => `${m.counts[k]} ${SHOW_KIND_LABEL[k]}`).join(", ") || "none"}`];
  if (m.cloaking?.agentOnly.length) tail.push(`${m.cloaking.agentOnly.length} passage(s) served only to AI fetchers`);
  return [head, "", ...lines, "", dim(tail.join("\n"))].join("\n");
}

// ---------- arguments ----------

export interface ShowArgs { target?: string; out?: string; open: boolean; term: boolean; error?: string }

export function parseShowArgs(a: string[]): ShowArgs {
  const r: ShowArgs = { open: false, term: false };
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    if (x === "--open") r.open = true;
    else if (x === "--term") r.term = true;
    else if (x === "--out") { r.out = a[++i]; if (!r.out) r.error = "--out needs a file name"; }
    else if (x.startsWith("--out=")) r.out = x.slice(6);
    else if (x.startsWith("--")) { /* engine flags (--policy=, --no-cloaking, --sandbox=) are read by the caller */ }
    else if (!r.target) r.target = x;
    else r.error = `unexpected argument ${x}`;
  }
  return r;
}

export const SHOW_USAGE = "usage: ingress show <url|file> [--out report.html] [--open]   one HTML page: what a person sees beside what your AI agent receives\n       ingress show --term <url|file>                          the same in the terminal, hidden spans in red brackets";
