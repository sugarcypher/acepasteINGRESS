/**
 * Visibility pass.
 *
 * Labels every piece of text by whether a sighted human reading the rendered
 * page would see it. Static only: inline styles, hidden attributes, the
 * page's own <style> blocks and any same-origin stylesheets the engine
 * fetched are consulted. Script-applied styles belong to the sandbox.
 *
 * Also extracts every <script> for the script pass. Traversal is iterative:
 * attacker-controlled nesting depth must not be able to crash the gate.
 */

import { parse, defaultTreeAdapter } from "parse5";
import type { DefaultTreeAdapterMap } from "parse5";
import type { Finding, ScriptUnit, TextSegment } from "./types.js";
import { decodeEntities } from "./adapters.js";

type Node = DefaultTreeAdapterMap["node"];
type Element = DefaultTreeAdapterMap["element"];

/** never rendered and never read by a human; still scanned as hidden text */
const HIDDEN_CONTAINER_TAGS = new Set(["noscript", "template"]);
/** not rendered as page copy at all; skipped (scripts are collected separately) */
const SKIPPED_TAGS = new Set(["script", "style", "head", "meta", "link", "base"]);
const A11Y_CLASS_HINTS = /\b(sr-only|visually-hidden|screen-reader-only|visuallyhidden|a11y-hidden|screen-reader-text|visually-hidden-focusable)\b/i;
const HIDDEN_CLASS_HINTS = /\b(hidden|offscreen|clip|is-hidden|d-none|invisible)\b/i;

export interface HiddenRule {
  selector: string; // simplified: ".class", "#id", or "tag"
  reason: TextSegment["visibility"];
}

/** Classify a style declaration string. Returns the hiding reason or null. */
export function classifyStyle(style: string): TextSegment["visibility"] | null {
  const s = style.toLowerCase().replace(/\s+/g, "");
  if (/display:none/.test(s) || /visibility:(hidden|collapse)/.test(s)) return "css_hidden";
  if (/content-visibility:hidden/.test(s)) return "css_hidden";
  const op = s.match(/opacity:(0?\.\d+|0|1)(?![\d.])/);
  if (op && Number(op[1]) < 0.1) return "tiny_or_transparent";
  const fs = s.match(/font-size:(\d*\.?\d+)(px|pt|em|rem|%)?/);
  if (fs && Number(fs[1]) <= (fs[2] === "em" || fs[2] === "rem" ? 0.1 : fs[2] === "%" ? 10 : 1)) return "tiny_or_transparent";
  if (/color:transparent/.test(s) || /color:rgba\([^)]*,0\)/.test(s) || /color:#[0-9a-f]{6}00\b/.test(s)) return "tiny_or_transparent";
  if (/transform:[^;]*scale(x|y|3d)?\(0(\.0+)?[,)]/.test(s) || /transform:[^;]*scale(x|y)?\(0\.0\d/.test(s)) return "tiny_or_transparent";
  if (/filter:[^;]*opacity\(0(\.0\d*)?\)/.test(s)) return "tiny_or_transparent";
  if (/(^|;)scale:0(\.0\d*)?(\s|;|$)/.test(s)) return "tiny_or_transparent";
  if (/(^|;)translate:-?\d{3,}(px|em|rem|vw|vh|%)/.test(s)) return "offscreen";
  if (/(^|;)inset:[^;]*-\d{3,}(px|em|rem|vw|vh|%)/.test(s)) return "offscreen";
  if (/(^|;)font:[^;]*(^|\s|:)0(px|pt|em|rem|%)?\/|(^|;)font:0(px)?(\s|\/|;|$)/.test(s)) return "tiny_or_transparent";
  // a custom property driving display/visibility/opacity/transform cannot be resolved statically; treat as hidden (hidden text is never delivered, so the cost of being wrong is low)
  if (/(display|visibility|opacity|transform|clip-path|font-size|scale|translate):var\(/.test(s)) return "css_hidden";
  if (/transform:[^;]*translate(x|y|3d)?\(-?\d{3,}(px|em|rem|vw|vh)/.test(s)) return "offscreen";
  { const fg = s.match(/(?:^|;)color:(#[0-9a-f]{3,8}|[a-z]+|rgba?\([^)]*\))/); const bg = s.match(/background(?:-color)?:(#[0-9a-f]{3,8}|[a-z]+|rgba?\([^)]*\))/); if (fg && bg && fg[1] === bg[1]) return "tiny_or_transparent"; }
  if (/-webkit-text-fill-color:transparent/.test(s)) return "tiny_or_transparent";
  if (/(left|top|right|bottom|margin-left|margin-top|text-indent):-\d{3,}(px|em|rem|%|vw|vh)/.test(s)) return "offscreen";
  if (/text-indent:(1\d\d|[2-9]\d\d|\d{4,})%/.test(s) || /text-indent:\d{4,}px/.test(s)) return "offscreen";
  if (/position:(absolute|fixed)/.test(s) && /(left|top):\d{4,}(px|vw|vh)/.test(s)) return "offscreen";
  if (/clip:rect\(0(px)?,0(px)?,0(px)?,0(px)?\)/.test(s) || /clip:rect\(1px,1px,1px,1px\)/.test(s)) return "offscreen";
  if (/clip-path:(inset\(([4-9]\d|100)%|circle\(0|polygon\(0(px|%)?\s*0)/.test(s)) return "offscreen";
  if (/(width|height|max-height|max-width):0(px)?;.*overflow:hidden/.test(s) || /overflow:hidden;.*(width|height|max-height|max-width):0(px)?(;|$)/.test(s)) return "offscreen";
  if (/(width|height):1px;.*overflow:hidden/.test(s) && /position:absolute/.test(s)) return "offscreen";
  return null;
}

export function rulesFromCss(cssIn: string): HiddenRule[] {
  const rules: HiddenRule[] = [];
  // flatten @media / @supports wrappers: "@media x { a{..} }" -> "a{..}"; drop keyframes and comments
  const css = cssIn
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/@keyframes[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}/g, "")
    .replace(/@(media|supports|layer|container)[^{]*\{/g, "");
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = re.exec(css)) && count++ < 20000) {
    const reason = classifyStyle(m[2]);
    if (!reason) continue;
    for (const sel of m[1].split(",")) {
      const t = sel.trim();
      if (/^[.#]?[\w-]+$/.test(t)) { rules.push({ selector: t, reason }); continue; }
      // compound/descendant selectors: key on the last simple class or id; over-matching only raises suspicion
      const last = t.split(/[\s>+~]+/).pop() ?? "";
      const simple = last.match(/[.#][\w-]+/g);
      if (simple) rules.push({ selector: simple[simple.length - 1], reason });
    }
  }
  return rules;
}

function attr(el: Element, name: string): string | undefined {
  return el.attrs.find((a) => a.name === name)?.value;
}

function matchesRule(el: Element, rule: HiddenRule): boolean {
  if (rule.selector.startsWith(".")) {
    const cls = attr(el, "class") ?? "";
    return cls.split(/\s+/).includes(rule.selector.slice(1));
  }
  if (rule.selector.startsWith("#")) return attr(el, "id") === rule.selector.slice(1);
  return el.tagName === rule.selector;
}

export interface VisibilityResult {
  segments: TextSegment[];
  scripts: ScriptUnit[];
  findings: Finding[];
  /** concatenated visible text, whitespace-normalized */
  visibleText: string;
  /** hrefs of linked stylesheets, resolved by the caller */
  stylesheetLinks: string[];
  /** maximum element nesting depth seen */
  maxDepth: number;
}

function children(n: Node): Node[] {
  return ((n as { childNodes?: Node[] }).childNodes ?? []) as Node[];
}

/** Collect hrefs of <link rel=stylesheet> so the engine can fetch them (same origin) before the real pass. */
export function findStylesheetLinks(html: string): string[] {
  const out: string[] = [];
  const stack: Node[] = [parse(html)];
  while (stack.length) {
    const n = stack.pop()!;
    if (defaultTreeAdapter.isElementNode(n) && n.tagName === "link") {
      const rel = (attr(n, "rel") ?? "").toLowerCase();
      const href = attr(n, "href");
      if (/\bstylesheet\b/.test(rel) && href) out.push(href);
    }
    for (const c of children(n)) stack.push(c);
  }
  return out;
}

interface Frame { node: Node; vis: TextSegment["visibility"]; path: string; depth: number; inA11y: boolean }

export function analyzeHtml(html: string, externalRules: HiddenRule[] = []): VisibilityResult {
  const doc = parse(html);
  const segments: TextSegment[] = [];
  const scripts: ScriptUnit[] = [];
  const findings: Finding[] = [];
  const stylesheetLinks: string[] = [];
  const styleRules: HiddenRule[] = [...externalRules];
  let maxDepth = 0;

  // pass 1: <style> rules and stylesheet links (iterative)
  {
    const stack: Node[] = [doc];
    while (stack.length) {
      const n = stack.pop()!;
      if (defaultTreeAdapter.isElementNode(n)) {
        if (n.tagName === "style") {
          const css = n.childNodes.map((c) => (defaultTreeAdapter.isTextNode(c) ? c.value : "")).join("");
          styleRules.push(...rulesFromCss(css));
        }
        if (n.tagName === "link" && /\bstylesheet\b/.test((attr(n, "rel") ?? "").toLowerCase()) && attr(n, "href")) stylesheetLinks.push(attr(n, "href")!);
      }
      for (const c of children(n)) stack.push(c);
    }
  }

  // pass 2: segments and scripts (iterative, document order)
  let scriptIndex = 0;
  const stack: Frame[] = [{ node: doc, vis: "visible", path: "", depth: 0, inA11y: false }];
  const a11yShort = new Set<TextSegment>();
  while (stack.length) {
    const { node: n, vis: inherited, path, depth, inA11y } = stack.pop()!;
    if (depth > maxDepth) maxDepth = depth;

    if (defaultTreeAdapter.isCommentNode(n)) {
      const text = decodeEntities(n.data).text.trim();
      if (text) segments.push({ text, visibility: "comment", path: `${path}#comment` });
      continue;
    }
    if (defaultTreeAdapter.isTextNode(n)) {
      const text = n.value;
      if (text.trim()) {
        const seg: TextSegment = { text, visibility: inherited, path };
        segments.push(seg);
        if (inA11y) a11yShort.add(seg);
      }
      continue;
    }
    if (!defaultTreeAdapter.isElementNode(n)) {
      const kids = children(n);
      for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i], vis: inherited, path, depth, inA11y });
      continue;
    }

    const el = n;
    const tag = el.tagName;
    const myPath = `${path}/${tag}`;

    if (tag === "script") {
      const src = attr(el, "src");
      const source = el.childNodes.map((c) => (defaultTreeAdapter.isTextNode(c) ? c.value : "")).join("");
      if (scripts.length < 2000) scripts.push({ index: scriptIndex++, source, inline: !src, src });
      continue;
    }
    if (tag === "title") {
      const t = el.childNodes.map((c) => (defaultTreeAdapter.isTextNode(c) ? c.value : "")).join("").trim();
      if (t) segments.push({ text: t, visibility: "attribute", path: `${myPath}` });
      continue;
    }
    if (tag === "meta") {
      const name = (attr(el, "name") ?? attr(el, "property") ?? "").toLowerCase();
      const content = attr(el, "content");
      if (content && /description|keywords|og:|twitter:/.test(name) && content.trim()) segments.push({ text: content, visibility: "attribute", path: `${myPath}@${name}` });
      continue;
    }
    if (tag === "iframe") {
      const srcdoc = attr(el, "srcdoc");
      if (srcdoc && srcdoc.trim()) segments.push({ text: srcdoc.replace(/<[^>]+>/g, " "), visibility: "css_hidden", path: `${myPath}@srcdoc` });
      continue;
    }
    if (SKIPPED_TAGS.has(tag)) continue;
    if (tag === "svg" && inherited === "visible") {
      // SVG text renders, but as graphics: scan it as its own channel, do not deliver it as page copy
      const kids = el.childNodes;
      for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i], vis: "attribute", path: `${myPath}@svg`, depth: depth + 1, inA11y });
      continue;
    }

    // attribute-only text: alt, title, aria-label, placeholder, value, data-*
    for (const a of el.attrs) {
      if (["alt", "title", "aria-label", "aria-description", "placeholder", "value", "label"].includes(a.name) || a.name.startsWith("data-")) {
        if (a.value.trim().length > 0) segments.push({ text: a.value, visibility: "attribute", path: `${myPath}@${a.name}` });
      }
    }

    let vis = inherited;
    let a11y = inA11y;
    if (vis === "visible") {
      if (attr(el, "hidden") !== undefined || attr(el, "aria-hidden") === "true" || attr(el, "inert") !== undefined) vis = "css_hidden";
      if (HIDDEN_CONTAINER_TAGS.has(tag)) vis = "css_hidden";
      if (tag === "details" && attr(el, "open") === undefined) vis = "css_hidden"; // summary re-opened below
      if (tag === "input" && /^(hidden)$/i.test(attr(el, "type") ?? "")) vis = "css_hidden";
      const style = attr(el, "style");
      if (style) vis = classifyStyle(style) ?? vis;
      if (vis === "visible") for (const r of styleRules) if (matchesRule(el, r)) { vis = r.reason; break; }
      const cls = attr(el, "class") ?? "";
      if (vis === "visible" && A11Y_CLASS_HINTS.test(cls)) { vis = "css_hidden"; a11y = true; }
      if (vis === "visible" && HIDDEN_CLASS_HINTS.test(cls)) vis = "css_hidden";
    }

    const kids = el.childNodes;
    for (let i = kids.length - 1; i >= 0; i--) {
      const c = kids[i];
      // the <summary> of a collapsed <details> is visible
      const childVis = tag === "details" && defaultTreeAdapter.isElementNode(c) && c.tagName === "summary" && inherited === "visible" ? "visible" : vis;
      stack.push({ node: c, vis: childVis, path: myPath, depth: depth + 1, inA11y: a11y });
    }
  }

  // findings: any non-visible text that is long enough to carry an instruction
  const kindFor: Record<Exclude<TextSegment["visibility"], "visible">, Finding["kind"]> = {
    css_hidden: "visibility.css_hidden",
    offscreen: "visibility.offscreen",
    attribute: "visibility.attribute_only",
    comment: "visibility.html_comment",
    tiny_or_transparent: "visibility.tiny_or_transparent",
  };
  for (const s of segments) {
    if (s.visibility === "visible") continue;
    const words = s.text.trim().split(/\s+/).length;
    // short hidden text is page furniture; attributes (alt, title) are routinely a sentence long
    if (words < (s.visibility === "attribute" ? 14 : 6)) continue;
    const isA11y = a11yShort.has(s) && words < 20;
    const base = s.visibility === "attribute" ? 0.15 : isA11y ? 0.3 : 0.55;
    findings.push({
      pass: "visibility",
      kind: kindFor[s.visibility],
      confidence: Math.min(0.95, base + Math.min(words, 60) / 120),
      // hidden text is not delivered, so on its own it is informational; the meaning pass decides whether it is an attack
      severity: 0.35,
      message: `${words} words of ${s.visibility.replace(/_/g, " ")} text a human would not see${isA11y ? " (screen-reader label)" : ""}`,
      excerpt: s.text.trim().slice(0, 160),
      location: s.path,
      action: "none",
    });
  }

  const visibleText = segments
    .filter((s) => s.visibility === "visible")
    .map((s) => s.text)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();

  return { segments, scripts, findings, visibleText, stylesheetLinks, maxDepth };
}
