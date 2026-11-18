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
import { colorsFromStyle, contrastRatio, blend, parseColor, INVISIBLE_CONTRAST, type RGBA } from "./color.js";

type Node = DefaultTreeAdapterMap["node"];
type Element = DefaultTreeAdapterMap["element"];

/** never rendered and never read by a human; still scanned as hidden text */
const HIDDEN_CONTAINER_TAGS = new Set(["noscript", "template"]);
/** not rendered as page copy at all; skipped (scripts are collected separately) */
const SKIPPED_TAGS = new Set(["script", "style", "head", "meta", "link", "base"]);
/**
 * Class names that hide an element by convention, matched as whole class names. Matching inside names read
 * `overflow-hidden`, `overflow-x-clip` and `bg-clip-text` as "hidden" and "clip", and hid the main column of
 * every page that clips its overflow.
 */
const A11Y_CLASSES = new Set(["sr-only", "visually-hidden", "screen-reader-only", "visuallyhidden", "a11y-hidden", "screen-reader-text", "visually-hidden-focusable"]);
const HIDDEN_CLASSES = new Set(["hidden", "offscreen", "is-hidden", "d-none", "invisible", "u-hidden", "hide", "is-invisible"]);
/** utility-framework variants: `md:block` shows at a width, `dark:block` in a theme, `not-sr-only` undoes sr-only */
const SHOWS_AT_A_WIDTH_OR_THEME = /^(?:sm|md|lg|xl|2xl|dark|light|print|max-(?:sm|md|lg|xl|2xl)|min-\[[^\]]+\]|supports-\[[^\]]+\]):(?:block|flex|grid|inline|inline-block|inline-flex|inline-grid|table|table-cell|contents|flow-root|list-item|visible|not-sr-only)$/;
const HIDES_ON_DESKTOP = /^(?:sm|md|lg|xl|2xl):(?:hidden|invisible|sr-only)$/;

/** How an element's class names hide it, if they do. A person at a desktop width in either theme is the reference. */
function classHides(cls: string): { vis: "css_hidden"; a11y: boolean } | null {
  const tokens = cls.toLowerCase().split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;
  const shownSomewhere = tokens.some((t) => SHOWS_AT_A_WIDTH_OR_THEME.test(t));
  if (tokens.some((t) => A11Y_CLASSES.has(t)) && !tokens.includes("not-sr-only") && !shownSomewhere) return { vis: "css_hidden", a11y: true };
  // `hidden lg:block` is a desktop sidebar: hidden on a phone, shown to the reader we model
  if (tokens.some((t) => HIDDEN_CLASSES.has(t)) && !shownSomewhere) return { vis: "css_hidden", a11y: false };
  // `lg:hidden` is the phone menu: not shown at desktop width
  if (tokens.some((t) => HIDES_ON_DESKTOP.test(t))) return { vis: "css_hidden", a11y: false };
  return null;
}

export interface HiddenRule {
  selector: string; // simplified: ".class", "#id", or "tag"
  reason: TextSegment["visibility"];
  /** other classes the element must also have (`.a.b` is keyed on b and requires a) */
  all?: string[];
  /** classes the element must not have (`:not(.show)`) */
  not?: string[];
  /** tag the element must be (`div.note`) */
  tag?: string;
}

/** Custom properties (`--name`) and every value a stylesheet or inline style gives them. */
export type CssVars = Map<string, Set<string>>;

/**
 * Split a declaration block into property -> value (lower case, whitespace removed, `!important` dropped).
 * The last declaration of a property wins, as in the cascade. Semicolons inside parentheses or quotes
 * (a data: URL) do not split.
 */
export function parseDeclarations(style: string): Map<string, string> {
  const out = new Map<string, string>();
  let depth = 0, quote = "", start = 0;
  const flush = (end: number) => {
    const d = style.slice(start, end);
    const i = d.indexOf(":");
    if (i > 0) {
      const prop = d.slice(0, i).trim().toLowerCase();
      const value = d.slice(i + 1).toLowerCase().replace(/\s+/g, "").replace(/!important$/, "");
      if (prop && value) { out.delete(prop); out.set(prop, value); }
    }
    start = end + 1;
  };
  for (let i = 0; i < style.length; i++) {
    const c = style[i];
    if (quote) { if (c === quote && style[i - 1] !== "\\") quote = ""; continue; }
    if (c === '"' || c === "'") quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === ";" && depth === 0) flush(i);
  }
  flush(style.length);
  return out;
}

/** Collect custom property definitions from CSS text (rule bodies or one inline style). */
export function collectCssVars(css: string, into: CssVars = new Map()): CssVars {
  for (const m of css.matchAll(/(--[\w-]+)\s*:\s*([^;{}]+)/g)) {
    const v = m[2].toLowerCase().replace(/\s+/g, "").replace(/!important$/, "");
    if (!v) continue;
    const set = into.get(m[1].toLowerCase()) ?? new Set<string>();
    if (set.size < 12) set.add(v);
    into.set(m[1].toLowerCase(), set);
  }
  return into;
}

/**
 * Every value a declaration could take once its var() references are resolved: each known definition of
 * the variable, and the fallback. A variable nobody defines statically resolves to nothing: its value is
 * unknown, and unknown is not hidden. (Tailwind 4 sets every text size as `font-size:var(--text-sm)`;
 * reading that as "hidden" marked whole sites as hidden text.)
 */
function candidates(value: string, vars: CssVars | undefined, depth = 0): string[] {
  const m = value.match(/var\((--[\w-]+)(?:,([^()]*(?:\([^()]*\)[^()]*)*))?\)/);
  if (!m || depth > 4) return [value];
  const defs = [...(vars?.get(m[1]) ?? [])];
  if (m[2] !== undefined && m[2] !== "") defs.push(m[2]);
  const out: string[] = [];
  for (const d of defs.slice(0, 12)) out.push(...candidates(value.replace(m[0], d), vars, depth + 1));
  return out.slice(0, 24);
}

const ZERO_ALPHA_COLOR = /^(?:transparent|rgba?\([^)]*[,/]0(?:\.0+)?%?\)|hsla?\([^)]*[,/]0(?:\.0+)?%?\)|#[0-9a-f]{6}00|#[0-9a-f]{3}0)$/;
const num = (v: string) => { const m = v.match(/^(-?\d*\.?\d+)(px|pt|em|rem|%|vw|vh)?$/); return m ? { n: Number(m[1]), unit: m[2] ?? "" } : undefined; };

/** One property with one concrete value: does it hide the element's text? */
function hidesByProperty(prop: string, v: string): TextSegment["visibility"] | null {
  switch (prop) {
    case "display": return v === "none" ? "css_hidden" : null;
    case "visibility": return v === "hidden" || v === "collapse" ? "css_hidden" : null;
    case "content-visibility": return v === "hidden" ? "css_hidden" : null;
    case "opacity": { const x = num(v); return x && (x.unit === "%" ? x.n < 10 : x.unit === "" && x.n < 0.1) ? "tiny_or_transparent" : null; }
    case "font-size": { const x = num(v); return x && x.n <= (x.unit === "em" || x.unit === "rem" ? 0.1 : x.unit === "%" ? 10 : 1) ? "tiny_or_transparent" : null; }
    case "color": case "-webkit-text-fill-color": return ZERO_ALPHA_COLOR.test(v) ? "tiny_or_transparent" : null;
    case "transform": case "-webkit-transform":
      if (/scale(x|y|3d)?\(0(\.0+)?[,)]/.test(v) || /scale(x|y)?\(0\.0\d/.test(v)) return "tiny_or_transparent";
      return /translate(x|y|3d)?\(-?\d{3,}(px|em|rem|vw|vh)/.test(v) ? "offscreen" : null;
    case "filter": return /opacity\(0(\.0\d*)?%?\)/.test(v) ? "tiny_or_transparent" : null;
    case "scale": return /^0(\.0\d*)?($|[^\d.])/.test(v) ? "tiny_or_transparent" : null;
    case "translate": return /^-?\d{3,}(px|em|rem|vw|vh|%)/.test(v) ? "offscreen" : null;
    case "inset": return /-\d{3,}(px|em|rem|vw|vh|%)/.test(v) ? "offscreen" : null;
    case "font": return /(^|[^\d.])0(px|pt|em|rem|%)?\//.test(v) || /^0(px)?(\/|$)/.test(v) ? "tiny_or_transparent" : null;
    case "left": case "top": case "right": case "bottom": case "margin-left": case "margin-top":
      return /^-\d{3,}(px|em|rem|%|vw|vh)/.test(v) ? "offscreen" : null;
    case "text-indent": return /^-\d{3,}(px|em|rem|%|vw|vh)/.test(v) || /^(1\d\d|[2-9]\d\d|\d{4,})%/.test(v) || /^\d{4,}px/.test(v) ? "offscreen" : null;
    case "clip": return /^rect\(0(px)?,?0(px)?,?0(px)?,?0(px)?\)/.test(v) || /^rect\(1px,?1px,?1px,?1px\)/.test(v) ? "offscreen" : null;
    case "clip-path": return /^(inset\(([4-9]\d|100)%|circle\(0|polygon\(0(px|%)?0)/.test(v) ? "offscreen" : null;
    default: return null;
  }
}

/**
 * Classify a declaration block. Returns the hiding reason or null. Properties are matched by their exact
 * names (so `-webkit-tap-highlight-color:transparent`, `background-color:rgba(0,0,0,0)` and
 * `fill-opacity:0` hide nothing), and var() references are resolved against `vars` before judging.
 */
export function classifyStyle(style: string, vars?: CssVars): TextSegment["visibility"] | null {
  const d = parseDeclarations(style);
  // variables this very block defines apply to it too (style="--o:0;opacity:var(--o)")
  let scope = vars;
  for (const [p, v] of d) if (p.startsWith("--")) { scope = scope === vars ? new Map(vars ?? []) : scope; const s = new Set(scope!.get(p) ?? []); s.add(v); scope!.set(p, s); }
  for (const [prop, value] of d) {
    if (prop.startsWith("--")) continue;
    for (const v of value.includes("var(") ? candidates(value, scope) : [value]) {
      const r = hidesByProperty(prop, v);
      if (r) return r;
    }
  }
  // combinations
  const get = (p: string) => d.get(p) ?? "";
  const zero = (p: string) => /^0(px)?$/.test(get(p));
  const clips = get("overflow") === "hidden" || get("overflow-x") === "hidden" || get("overflow-y") === "hidden";
  if (clips && (zero("width") || zero("height") || zero("max-height") || zero("max-width"))) return "offscreen";
  if (clips && (get("width") === "1px" || get("height") === "1px") && get("position") === "absolute") return "offscreen";
  if (/^(absolute|fixed)$/.test(get("position")) && (/^\d{4,}(px|vw|vh)/.test(get("left")) || /^\d{4,}(px|vw|vh)/.test(get("top")))) return "offscreen";
  return null;
}

/** Split a selector list on commas that are not inside parentheses or brackets (`:is(.a, .b)` is one selector). */
function splitSelectors(list: string): string[] {
  const out: string[] = [];
  let depth = 0, start = 0;
  for (let i = 0; i < list.length; i++) {
    const c = list[i];
    if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") depth = Math.max(0, depth - 1);
    else if (c === "," && depth === 0) { out.push(list.slice(start, i)); start = i + 1; }
  }
  out.push(list.slice(start));
  return out.map((s) => s.trim()).filter(Boolean);
}

/** an ancestor that names a theme, a state or a script-set class: the rule applies in one mode of the page, not always */
const CONDITIONAL_ANCESTOR = /(^|[.#\[="'_-])(dark|light|theme|mode|print|no-?js|js|open|opened|closed|active|inactive|collapsed|expanded|loading|loaded|ready|is-|has-)/i;

/**
 * Turn one selector into a rule the static pass can apply, or nothing when the selector does not describe
 * what a reader at a desktop sees by default:
 *   - a pseudo-element (`::-webkit-scrollbar`, `::before`) styles another box, not the element's text.
 *     `.scroll::-webkit-scrollbar{display:none}` hides a scrollbar; read as hiding `.scroll`, it hid every
 *     table on a documentation page.
 *   - a state (`:hover`, `:checked`, `[data-state=closed]`, `[hidden]`) holds only sometimes. The `hidden`
 *     attribute itself is handled where elements are read.
 *   - an ancestor that names a theme or a state makes the rule one mode of the page.
 * `:not(.class)` on the element is kept and checked (`.collapse:not(.show)`).
 */
function ruleFromSelector(sel: string, reason: TextSegment["visibility"]): HiddenRule | null {
  if (/^[.#]?[\w-]+$/.test(sel)) return { selector: sel, reason };
  const parts = sel.replace(/\s*([>+~])\s*/g, " $1 ").split(/\s+/).filter((p) => p && !/^[>+~]$/.test(p));
  const last = parts.pop() ?? "";
  if (/::|:(before|after|first-line|first-letter|placeholder|marker|selection|backdrop|file-selector-button)\b/i.test(last)) return null;
  if (last.includes("\\")) return null; // an escaped name (`.lg\:hidden`): a variant class, read from the class list instead
  const nots = [...last.matchAll(/:not\(\.([\w-]+)\)/g)].map((m) => m[1]);
  const bare = last.replace(/:not\(\.[\w-]+\)/g, "");
  if (/[:\[()*]/.test(bare)) return null; // any other pseudo-class or attribute test: a state
  if (parts.some((a) => /[:\[\\]/.test(a) || CONDITIONAL_ANCESTOR.test(a))) return null;
  const classes = (bare.match(/\.[\w-]+/g) ?? []).map((c) => c.slice(1));
  const id = bare.match(/#([\w-]+)/)?.[1];
  const tag = bare.match(/^[a-z][\w-]*/i)?.[0]?.toLowerCase();
  if (id) return { selector: `#${id}`, reason, all: classes, not: nots, tag };
  if (classes.length) return { selector: `.${classes[classes.length - 1]}`, reason, all: classes.slice(0, -1), not: nots, tag };
  if (tag && parts.length) return null; // `nav ul`: a tag under an ancestor over-matches every such tag on the page
  return tag ? { selector: tag, reason, not: nots } : null;
}

export function rulesFromCss(cssIn: string, extraVars?: CssVars): HiddenRule[] {
  const rules: HiddenRule[] = [];
  // media blocks that do not describe a desktop screen are dropped; the rest of the @-wrappers are flattened:
  // "@media x { a{..} }" -> "a{..}". Keyframes and comments are dropped.
  const css = dropAlternateMedia(cssIn.replace(/\/\*[\s\S]*?\*\//g, ""))
    .replace(/@keyframes[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}/g, "")
    .replace(/@(media|supports|layer|container)[^{]*\{/g, "");
  // custom properties defined anywhere in this stylesheet, so var() references can be resolved before judging
  const vars = collectCssVars(css, new Map(extraVars ?? []));
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = re.exec(css)) && count++ < 20000) {
    const reason = classifyStyle(m[2], vars);
    if (!reason) continue;
    for (const sel of splitSelectors(m[1])) {
      const r = ruleFromSelector(sel, reason);
      if (r) rules.push(r);
    }
  }
  return rules;
}

export interface ColorRule {
  selector: string; // ".class", "#id" or "tag" only: colour is applied only on simple selectors, so a compound rule cannot over-match into a false "hidden"
  fg?: RGBA | null;
  bg?: RGBA | null;
  fill?: RGBA | null;
}

/** widths below this are phones and small tablets: `@media (max-width: 767px)` does not describe a desktop screen */
const DESKTOP_MIN_PX = 1024;
function isAlternateMedia(query: string): boolean {
  const q = query.toLowerCase();
  if (/prefers-color-scheme\s*:\s*dark|\bprint\b|forced-colors|prefers-contrast|prefers-reduced-(motion|transparency)|\(\s*hover\s*:\s*none\s*\)|\(\s*pointer\s*:\s*coarse\s*\)|orientation\s*:\s*portrait/.test(q)) return true;
  // a width cap below desktop: `max-width: 767px`, `width <= 40rem`, `width < 640px`
  for (const m of q.matchAll(/(?:max-width\s*:|width\s*<=?)\s*(\d*\.?\d+)(px|em|rem)/g)) {
    const px = Number(m[1]) * (m[2] === "px" ? 1 : 16);
    if (px < DESKTOP_MIN_PX) return true;
  }
  return false;
}

/** Remove @media blocks that do not describe the default desktop screen (dark mode, print, phone widths), brace-matched. */
function dropAlternateMedia(css: string): string {
  let out = "", i = 0;
  const re = /@media([^{]*)\{/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(css))) {
    if (!isAlternateMedia(m[1])) continue;
    out += css.slice(i, m.index);
    let depth = 1, j = m.index + m[0].length;
    while (j < css.length && depth > 0) { if (css[j] === "{") depth++; else if (css[j] === "}") depth--; j++; }
    i = j; re.lastIndex = j;
  }
  return out + css.slice(i);
}

export function colorRulesFromCss(cssIn: string): ColorRule[] {
  const rules: ColorRule[] = [];
  const css = dropAlternateMedia(cssIn.replace(/\/\*[\s\S]*?\*\//g, ""))
    .replace(/@keyframes[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}/g, "")
    .replace(/@(media|supports|layer|container)[^{]*\{/g, "");
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = re.exec(css)) && count++ < 20000) {
    if (!/color|background/i.test(m[2])) continue;
    const c = colorsFromStyle(m[2]);
    if (c.fg === undefined && c.bg === undefined && c.fill === undefined) continue;
    for (const sel of m[1].split(",")) {
      const t = sel.trim().toLowerCase();
      if (/^([.#][\w-]+|[a-z][\w-]*|:root)$/.test(t)) { rules.push({ selector: t === ":root" ? "html" : t, ...c }); continue; }
      // a colour set through a compound, attribute or pseudo selector cannot be resolved statically: mark the colour
      // unknown on the element it keys on, so the element is never judged hidden on a guess (over-matching only loses detection)
      const last = t.split(/[\s>+~]+/).pop() ?? "";
      const key = (last.match(/[.#][\w-]+/g) ?? []).pop() ?? (last.match(/^[a-z][\w-]*/) ?? [])[0];
      if (!key) continue;
      rules.push({ selector: key, ...(c.fg !== undefined ? { fg: null } : {}), ...(c.fill !== undefined ? { fill: null } : {}), ...(c.bg !== undefined ? { bg: null } : {}) });
    }
  }
  return rules;
}

function attr(el: Element, name: string): string | undefined {
  return el.attrs.find((a) => a.name === name)?.value;
}

function matchesRule(el: Element, rule: HiddenRule): boolean {
  const classes = (attr(el, "class") ?? "").split(/\s+/);
  if (rule.tag && rule.selector !== rule.tag && el.tagName !== rule.tag) return false;
  if (rule.all?.some((c) => !classes.includes(c))) return false;
  if (rule.not?.some((c) => classes.includes(c))) return false;
  if (rule.selector.startsWith(".")) return classes.includes(rule.selector.slice(1));
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

interface Frame { node: Node; vis: TextSegment["visibility"]; path: string; depth: number; inA11y: boolean; fg: RGBA | null; bg: RGBA | null; fill?: RGBA | null }

const BROWSER_FG: RGBA = { r: 0, g: 0, b: 0, a: 1 };
const BROWSER_BG: RGBA = { r: 255, g: 255, b: 255, a: 1 };

export function analyzeHtml(html: string, externalRules: HiddenRule[] = [], externalColorRules: ColorRule[] = []): VisibilityResult {
  const doc = parse(html);
  const segments: TextSegment[] = [];
  const scripts: ScriptUnit[] = [];
  const findings: Finding[] = [];
  const stylesheetLinks: string[] = [];
  const styleRules: HiddenRule[] = [...externalRules];
  const colorRules: ColorRule[] = [...externalColorRules];
  /** segments hidden by colour, with the measured contrast */
  const lowContrast = new Map<TextSegment, number>();
  const lowContrastRatio = new Map<string, number>();
  let maxDepth = 0;
  /** custom properties defined in the page's own <style> blocks and style attributes */
  const cssVars: CssVars = new Map();
  const styleBlocks: string[] = [];

  // pass 1: <style> rules and stylesheet links (iterative)
  {
    const stack: Node[] = [doc];
    while (stack.length) {
      const n = stack.pop()!;
      if (defaultTreeAdapter.isElementNode(n)) {
        if (n.tagName === "style") {
          const css = n.childNodes.map((c) => (defaultTreeAdapter.isTextNode(c) ? c.value : "")).join("");
          styleBlocks.push(css);
          collectCssVars(css, cssVars);
          colorRules.push(...colorRulesFromCss(css));
        }
        // a custom property set in a style attribute can drive a rule elsewhere (style="--o:0" with opacity:var(--o))
        const inline = attr(n, "style");
        if (inline && inline.includes("--")) collectCssVars(inline, cssVars);
        if (n.tagName === "link" && /\bstylesheet\b/.test((attr(n, "rel") ?? "").toLowerCase()) && attr(n, "href")) stylesheetLinks.push(attr(n, "href")!);
      }
      for (const c of children(n)) stack.push(c);
    }
    // rules are classified once every variable the page defines is known, wherever it was defined
    for (const css of styleBlocks) styleRules.push(...rulesFromCss(css, cssVars));
  }

  // pass 2: segments and scripts (iterative, document order)
  let scriptIndex = 0;
  const stack: Frame[] = [{ node: doc, vis: "visible", path: "", depth: 0, inA11y: false, fg: BROWSER_FG, bg: BROWSER_BG }];
  // colour cascade, roughly by specificity: tag rules, then class, then id, then presentational attributes, then inline style
  const byTag = colorRules.filter((r) => !/^[.#]/.test(r.selector));
  const byClass = colorRules.filter((r) => r.selector.startsWith("."));
  const byId = colorRules.filter((r) => r.selector.startsWith("#"));
  const a11yShort = new Set<TextSegment>();
  while (stack.length) {
    const { node: n, vis: inherited, path, depth, inA11y, fg: inFg, bg: inBg, fill: inFill } = stack.pop()!;
    if (depth > maxDepth) maxDepth = depth;

    if (defaultTreeAdapter.isCommentNode(n)) {
      const text = decodeEntities(n.data).text.trim();
      if (text) segments.push({ text, visibility: "comment", path: `${path}#comment` });
      continue;
    }
    if (defaultTreeAdapter.isTextNode(n)) {
      const text = n.value;
      if (text.trim()) {
        // colour is judged where the text is: the colour it inherits against the background it sits on
        let visibility = inherited;
        const textColor = inFill ?? inFg;
        if (visibility === "visible" && textColor && inBg) {
          const ratio = contrastRatio(textColor, inBg);
          if (ratio <= INVISIBLE_CONTRAST) { visibility = "tiny_or_transparent"; lowContrastRatio.set(path + "\u0000" + segments.length, ratio); }
        }
        const seg: TextSegment = { text, visibility, path };
        const key = path + "\u0000" + segments.length;
        segments.push(seg);
        if (lowContrastRatio.has(key)) lowContrast.set(seg, lowContrastRatio.get(key)!);
        if (inA11y) a11yShort.add(seg);
      }
      continue;
    }
    if (!defaultTreeAdapter.isElementNode(n)) {
      const kids = children(n);
      for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i], vis: inherited, path, depth, inA11y, fg: inFg, bg: inBg, fill: inFill });
      continue;
    }

    const el = n;
    const tag = el.tagName;
    // content a reader reveals with one click (a collapsed <details>, a hidden tab panel) is marked so passes that
    // weigh visibility can treat it as documentation rather than concealment
    const revealable = (tag === "details" && attr(el, "open") === undefined) ||
      (attr(el, "hidden") !== undefined && (/^(tabpanel|region)$/i.test(attr(el, "role") ?? "") || /\b(tab|panel|accordion|collapse)/i.test(attr(el, "class") ?? "")));
    const myPath = `${path}/${tag}${revealable ? "~revealable" : ""}`;

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
      for (let i = kids.length - 1; i >= 0; i--) stack.push({ node: kids[i], vis: "attribute", path: `${myPath}@svg`, depth: depth + 1, inA11y, fg: inFg, bg: inBg, fill: inFill });
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

    // colour: resolve this element's text colour and the background it sits on
    let fg = inFg, bg = inBg, fill: RGBA | null | undefined = inFill;
    const apply = (c: { fg?: RGBA | null; bg?: RGBA | null; fill?: RGBA | null }) => {
      if (c.fg !== undefined) fg = c.fg;
      if (c.fill !== undefined) fill = c.fill;
      if (c.bg !== undefined) {
        if (c.bg === null) bg = null;                       // image or gradient: unknown, never flag
        else if (c.bg.a >= 0.999) bg = c.bg;
        else if (c.bg.a > 0 && bg) bg = blend(c.bg, bg);
      }
    };
    const clsList = (attr(el, "class") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
    const id = (attr(el, "id") ?? "").toLowerCase();
    for (const r of byTag) if (r.selector === tag) apply(r);
    for (const r of byClass) if (clsList.includes(r.selector.slice(1))) apply(r);
    if (id) for (const r of byId) if (r.selector === "#" + id) apply(r);
    const pres = (a: string) => { const v = attr(el, a); return v ? parseColor(v) : undefined; };
    if (tag === "font" && pres("color")) apply({ fg: pres("color") });
    if (tag === "body" && pres("text")) apply({ fg: pres("text") });
    if (pres("bgcolor")) apply({ bg: pres("bgcolor") });
    const inlineStyle = attr(el, "style");
    if (inlineStyle) apply(colorsFromStyle(inlineStyle));

    if (vis === "visible") {
      if (attr(el, "hidden") !== undefined || attr(el, "aria-hidden") === "true" || attr(el, "inert") !== undefined) vis = "css_hidden";
      if (HIDDEN_CONTAINER_TAGS.has(tag)) vis = "css_hidden";
      if (tag === "details" && attr(el, "open") === undefined) vis = "css_hidden"; // summary re-opened below
      if (tag === "input" && /^(hidden)$/i.test(attr(el, "type") ?? "")) vis = "css_hidden";
      const style = attr(el, "style");
      if (style) vis = classifyStyle(style, cssVars) ?? vis;
      if (vis === "visible") for (const r of styleRules) if (matchesRule(el, r)) { vis = r.reason; break; }
      if (vis === "visible") { const h = classHides(attr(el, "class") ?? ""); if (h) { vis = h.vis; a11y = a11y || h.a11y; } }
    }

    const kids = el.childNodes;
    for (let i = kids.length - 1; i >= 0; i--) {
      const c = kids[i];
      // the <summary> of a collapsed <details> is visible
      const childVis = tag === "details" && defaultTreeAdapter.isElementNode(c) && c.tagName === "summary" && inherited === "visible" ? "visible" : vis;
      stack.push({ node: c, vis: childVis, path: myPath, depth: depth + 1, inA11y: a11y, fg, bg, fill });
    }
  }

  // findings: any non-visible text that is long enough to carry an instruction
  const kindFor: Record<Exclude<TextSegment["visibility"], "visible">, Finding["kind"]> = {
    css_hidden: "visibility.css_hidden",
    offscreen: "visibility.offscreen",
    attribute: "visibility.attribute_only",
    comment: "visibility.html_comment",
    tiny_or_transparent: "visibility.tiny_or_transparent",
    concealed: "visibility.css_hidden", // not produced by the HTML pass; here so the map is total
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
      message: lowContrast.has(s)
        ? `${words} words in a colour matching their background (contrast ${lowContrast.get(s)!.toFixed(2)}:1) a human would not see`
        : `${words} words of ${s.visibility.replace(/_/g, " ")} text a human would not see${isA11y ? " (screen-reader label)" : ""}`,
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
