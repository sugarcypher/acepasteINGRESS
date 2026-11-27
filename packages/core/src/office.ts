/**
 * Office documents (DOCX, XLSX, PPTX): what a person sees in Word, Excel or PowerPoint, and what is in the
 * file for a machine only.
 *
 * Each is a ZIP of XML parts (read with zipread.ts, Node's zlib only). A text extractor takes every <t>; a
 * person sees only some of them. This module follows the formatting that decides which:
 *   DOCX  hidden text (w:vanish, w:specVanish, also through a style), white text, text under 2 points, tracked
 *         deletions, field codes, comments, alt text, custom XML parts, document properties, macros, a remote
 *         template (the "template injection" trick)
 *   XLSX  hidden and very hidden sheets, hidden rows and columns, cells formatted ";;;" (shown as nothing),
 *         white or tiny cell fonts, shared strings no cell uses, comments, alt text, custom XML, macros
 *   PPTX  hidden shapes, shapes placed off the slide, white or background-coloured text, text under 2 points,
 *         speaker notes, comments, alt text, custom XML, macros
 *
 * Limits: the page or slide background is taken to be light (white text counts as hidden; a dark theme makes
 * that a false alarm, reported as low confidence); colours from themes are read only for the bg1/lt1 names;
 * conditional formatting, group transforms in slides, and text inside embedded objects (OLE, charts, SmartArt
 * drawings) are not read; legacy binary formats (.doc, .xls, .ppt) are not read.
 */
import { readZip, type ZipRead } from "./zipread.js";
import type { Finding, TextSegment } from "./types.js";
import type { DocExtract } from "./filescan.js";

// ---------- XML ----------

interface Tok { kind: "open" | "close" | "text"; name: string; local: string; attrs: string; self: boolean; text: string }

const ENT: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };
export const xmlDecode = (s: string) => s.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, (_, e: string) => e[0] === "#" ? String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENT[e]);

function* tokens(xml: string): Generator<Tok> {
  const re = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<(\/?)([A-Za-z_][\w:.-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>|([^<]+)/g;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(xml)) && n++ < 5_000_000) {
    if (m[1] !== undefined) { yield { kind: "text", name: "", local: "", attrs: "", self: false, text: m[1] }; continue; }
    if (m[3]) {
      const name = m[3], local = name.includes(":") ? name.slice(name.indexOf(":") + 1) : name;
      yield { kind: m[2] ? "close" : "open", name, local, attrs: m[4] ?? "", self: !!m[5], text: "" };
      continue;
    }
    if (m[6] !== undefined) yield { kind: "text", name: "", local: "", attrs: "", self: false, text: xmlDecode(m[6]) };
  }
}
/** an attribute by local name (any prefix) */
function attr(attrs: string, local: string): string | undefined {
  const m = attrs.match(new RegExp(`(?:^|\\s)(?:[\\w.-]+:)?${local.replace(/[.]/g, "\\.")}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`));
  return m ? xmlDecode(m[1] ?? m[2] ?? "") : undefined;
}
const on = (attrs: string) => { const v = attr(attrs, "val"); return v === undefined || !/^(?:0|false|off)$/i.test(v); };
const isWhite = (hex?: string) => !!hex && /^(?:FF)?F[A-F0-9]F[A-F0-9]F[A-F0-9]$/i.test(hex) && (() => { const h = hex.slice(-6); return [0, 2, 4].every((i) => parseInt(h.slice(i, i + 2), 16) >= 0xf0); })();
const words = (s: string) => (s.match(/\p{L}{2,}/gu) ?? []).length;
const text = (b: Uint8Array | undefined) => (b ? new TextDecoder("utf-8", { fatal: false }).decode(b) : "");
/** every text node in a part, joined (comments, notes, custom XML) */
function allText(xml: string): string {
  const out: string[] = [];
  for (const t of tokens(xml)) {
    if (t.kind === "text") out.push(t.text);
    else if (t.kind === "close" && /^(?:p|si|comment|text|row|item)$/.test(t.local)) out.push("\n");
    else if (t.kind === "open" && t.self && /^(?:br|tab)$/.test(t.local)) out.push(" ");
  }
  return out.join("").replace(/[ \t]+/g, " ").replace(/\s*\n\s*/g, "\n").trim();
}

// ---------- shared ----------

export const OFFICE_HIDDEN: Record<string, { label: string; visibility: TextSegment["visibility"] }> = {
  vanish: { label: "formatted as hidden text", visibility: "css_hidden" },
  white: { label: "in white or the background colour", visibility: "tiny_or_transparent" },
  tiny: { label: "under 2 points tall", visibility: "tiny_or_transparent" },
  deleted: { label: "deleted with tracked changes (still in the file)", visibility: "concealed" },
  "field-code": { label: "in a field code", visibility: "attribute" },
  "hidden-sheet": { label: "on a hidden sheet", visibility: "concealed" },
  "very-hidden-sheet": { label: "on a very hidden sheet (cannot be unhidden from Excel's menus)", visibility: "concealed" },
  "hidden-row": { label: "in a hidden row", visibility: "concealed" },
  "hidden-column": { label: "in a hidden column", visibility: "concealed" },
  "blank-format": { label: "in cells formatted to show nothing (;;;)", visibility: "concealed" },
  "unused-string": { label: "stored in the workbook but in no cell", visibility: "concealed" },
  "hidden-shape": { label: "in a hidden shape", visibility: "concealed" },
  "off-slide": { label: "placed outside the slide", visibility: "offscreen" },
};

class Collector {
  segments: TextSegment[] = [];
  findings: Finding[] = [];
  notes: string[] = [];
  hidden = new Map<string, { text: string[]; where: Set<string> }>();
  constructor(public fmt: string) {}
  visible(t: string, path: string) { t = t.replace(/[ \t]+/g, " ").replace(/\s*\n\s*/g, "\n").trim(); if (t) this.segments.push({ text: t, visibility: "visible", path }); }
  hide(reason: string, t: string, where: string) {
    t = t.trim(); if (!t) return;
    const h = this.hidden.get(reason) ?? { text: [], where: new Set<string>() };
    h.text.push(t); h.where.add(where); this.hidden.set(reason, h);
  }
  other(t: string, visibility: TextSegment["visibility"], path: string) { t = t.trim(); if (t.length >= 3) this.segments.push({ text: t.slice(0, 100_000), visibility, path }); }
  finish(zip: ZipRead): DocExtract {
    for (const [reason, h] of this.hidden) {
      const t = h.text.join("\n");
      if (t.replace(/\s/g, "").length < 2) continue;
      const info = OFFICE_HIDDEN[reason];
      this.segments.push({ text: t.slice(0, 200_000), visibility: info.visibility, path: `${this.fmt}/hidden:${reason}` });
      const n = words(t);
      if (n >= 1 && reason !== "field-code") this.findings.push({ pass: "visibility", kind: "document.hidden_text", confidence: reason === "white" ? 0.15 : n >= 4 ? 0.3 : 0.1, severity: 0.4, message: `${n} word(s) are ${info.label} (${[...h.where].slice(0, 4).join(", ")}): an extractor reads them, a person does not see them${reason === "white" ? " (on a dark background this is ordinary text)" : ""}`, excerpt: t.slice(0, 160), location: `${this.fmt}/hidden:${reason}`, inHidden: true, action: "none" });
    }
    const said = (re: RegExp) => this.segments.filter((s) => re.test(s.path) && words(s.text) >= 4);
    const comments = said(/\/(?:comments|notes)/);
    if (comments.length) this.findings.push({ pass: "visibility", kind: "document.comment_text", confidence: 0.1, severity: 0.2, message: `comments or speaker notes hold text that is not on the page as shown (${comments.length} part(s))`, inHidden: true, action: "none" });
    const meta = said(/\/(?:properties|custom-xml|alt-text)/);
    if (meta.length) this.findings.push({ pass: "visibility", kind: "document.metadata_text", confidence: 0.1, severity: 0.2, message: `alt text, properties or custom XML parts hold text nobody reading the document sees (${[...new Set(meta.map((s) => s.path.split("/")[1]))].join(", ")})`, inHidden: true, action: "none" });
    for (const s of zip.skipped.slice(0, 5)) this.notes.push(`${s.name}: not read (${s.reason})`);
    this.notes.push(...zip.notes);
    return { format: this.fmt as DocExtract["format"], segments: this.segments, findings: this.findings, notes: this.notes, complete: !zip.skipped.some((s) => /\.xml$/i.test(s.name)) && !zip.notes.length };
  }
}

/** parts every Office format shares: properties, custom XML, macros, external relationships */
function common(zip: ZipRead, c: Collector, root: string): void {
  for (const p of ["docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"]) {
    const xml = text(zip.entries.get(p)); if (!xml) continue;
    for (const m of xml.matchAll(/<([\w]+:)?(title|subject|description|keywords|creator|lastModifiedBy|category|contentStatus|Company|Manager|lpwstr|vt:lpwstr)(?:\s[^>]*)?>([^<]{3,})</g)) {
      const t = xmlDecode(m[3]).trim();
      if (/^(?:creator|lastModifiedBy|Company|Manager)$/.test(m[2]) && words(t) < 6) continue;
      c.other(t, "attribute", `${c.fmt}/properties:${m[2]}`);
    }
  }
  for (const [name, data] of zip.entries) {
    if (/^customXml\/item\d*\.xml$/i.test(name)) { const t = allText(text(data)); if (words(t) >= 3) c.other(t, "concealed", `${c.fmt}/custom-xml:${name}`); }
  }
  const macros = [...zip.entries.keys()].filter((n) => /vbaProject\.bin$|\/activeX\/|vbaData\.xml$/i.test(n));
  if (macros.length) c.findings.push({ pass: "channel", kind: "document.active_content", confidence: 0.35, severity: 0.6, message: `the file carries macros or ActiveX controls (${macros.slice(0, 3).join(", ")}): code that runs in Office, not read here`, action: "none" });
  const embedded = [...zip.entries.keys()].filter((n) => /\/embeddings\//i.test(n));
  if (embedded.length) c.findings.push({ pass: "channel", kind: "document.embedded_content", confidence: 0.15, severity: 0.3, message: `${embedded.length} embedded object(s) were not opened or scanned (${embedded.slice(0, 3).join(", ")})`, action: "none" });
  for (const [name, data] of zip.entries) {
    if (!/\.rels$/.test(name)) continue;
    const xml = text(data);
    for (const m of xml.matchAll(/<Relationship\b([^>]*)>/g)) {
      if (!/TargetMode\s*=\s*"External"/i.test(m[1])) continue;
      const type = attr(m[1], "Type") ?? "", target = attr(m[1], "Target") ?? "";
      if (/attachedTemplate|oleObject|frame|subDocument/i.test(type)) c.findings.push({ pass: "channel", kind: "document.active_content", confidence: 0.5, severity: 0.65, message: `opening the file loads ${type.split("/").pop()} from outside it (${target.slice(0, 100)}): a remote template or object can carry macros or change what is shown`, action: "none" });
    }
  }
  void root;
}

function altTexts(xml: string, c: Collector, where: string): void {
  for (const m of xml.matchAll(/<(?:[\w]+:)?(?:docPr|cNvPr)\b([^>]*)>/g)) {
    for (const k of ["descr", "title"]) { const v = attr(m[1], k); if (v && v.trim().length >= 3) c.other(v, "concealed", `${c.fmt}/alt-text:${where}`); }
  }
}

// ---------- DOCX ----------

interface RunProps { vanish?: boolean; color?: string; sz?: number; shade?: string }

function docxStyles(xml: string): Map<string, RunProps & { basedOn?: string }> {
  const map = new Map<string, RunProps & { basedOn?: string }>();
  let cur: (RunProps & { basedOn?: string }) | undefined, inRpr = false;
  for (const t of tokens(xml)) {
    if (t.kind === "open" && t.local === "style") { cur = {}; map.set(attr(t.attrs, "styleId") ?? "", cur); }
    else if (t.kind === "close" && t.local === "style") cur = undefined;
    else if (cur && t.kind === "open" && t.local === "basedOn") cur.basedOn = attr(t.attrs, "val");
    else if (cur && t.kind === "open" && t.local === "rPr" && !t.self) inRpr = true;
    else if (t.kind === "close" && t.local === "rPr") inRpr = false;
    else if (cur && inRpr && t.kind === "open") readRunProp(t, cur);
  }
  return map;
}
function readRunProp(t: Tok, p: RunProps): void {
  if (t.local === "vanish" || t.local === "specVanish" || t.local === "webHidden") p.vanish = on(t.attrs);
  else if (t.local === "color") p.color = attr(t.attrs, "val");
  else if (t.local === "sz") { const v = Number(attr(t.attrs, "val")); if (v > 0) p.sz = v; }
  else if (t.local === "shd") p.shade = attr(t.attrs, "fill");
}
function styleProps(styles: Map<string, RunProps & { basedOn?: string }>, id: string | undefined): RunProps {
  const out: RunProps = {};
  for (let i = 0, cur = id; cur && i < 10; i++) {
    const s = styles.get(cur); if (!s) break;
    for (const k of ["vanish", "color", "sz", "shade"] as const) if (out[k] === undefined && s[k] !== undefined) (out as Record<string, unknown>)[k] = s[k];
    cur = s.basedOn;
  }
  return out;
}

function docxBody(xml: string, part: string, styles: Map<string, RunProps & { basedOn?: string }>, c: Collector): void {
  let pStyle: string | undefined, run: RunProps | undefined, rStyle: string | undefined, inRpr = false, inPpr = false, paraShade: string | undefined;
  let vis: string[] = [];
  const reasonOf = (): string | undefined => {
    const merged: RunProps = { ...styleProps(styles, pStyle), ...styleProps(styles, rStyle), ...Object.fromEntries(Object.entries(run ?? {}).filter(([, v]) => v !== undefined)) };
    if (merged.vanish) return "vanish";
    if (merged.sz !== undefined && merged.sz < 4) return "tiny";
    const bg = merged.shade && merged.shade !== "auto" ? merged.shade : paraShade && paraShade !== "auto" ? paraShade : "FFFFFF";
    const fg = merged.color && merged.color !== "auto" ? merged.color : "000000";
    if (fg.toUpperCase() === bg.toUpperCase() || (isWhite(fg) && isWhite(bg))) return "white";
    return undefined;
  };
  let field = false, deleted = false, inT = false;
  for (const t of tokens(xml)) {
    if (t.kind === "open" && !t.self && (t.local === "t" || t.local === "delText" || t.local === "instrText")) inT = true;
    else if (t.kind === "close" && (t.local === "t" || t.local === "delText" || t.local === "instrText")) inT = false;
    if (t.kind === "open") {
      switch (t.local) {
        case "p": if (!t.self) { pStyle = undefined; paraShade = undefined; } break;
        case "pPr": if (!t.self) inPpr = true; break;
        case "pStyle": pStyle = attr(t.attrs, "val"); break;
        case "r": if (!t.self) { run = {}; rStyle = undefined; } break;
        case "rPr": if (!t.self) inRpr = true; break;
        case "rStyle": rStyle = attr(t.attrs, "val"); break;
        case "del": if (!t.self) deleted = true; break;
        case "tab": if (t.self && !inRpr && !inPpr) vis.push("\t"); break;
        case "br": case "cr": if (t.self) vis.push("\n"); break;
        case "t": field = false; break;
        case "delText": field = false; break;
        case "instrText": field = true; break;
        default:
          if (inRpr && !inPpr && run) readRunProp(t, run);
          else if (inPpr && !inRpr && t.local === "shd") paraShade = attr(t.attrs, "fill");
      }
      if (t.local === "delText") deleted = true;
    } else if (t.kind === "close") {
      switch (t.local) {
        case "p": vis.push("\n"); break;
        case "pPr": inPpr = false; break;
        case "rPr": inRpr = false; break;
        case "r": run = undefined; rStyle = undefined; break;
        case "del": deleted = false; break;
        case "instrText": field = false; break;
      }
    } else if (t.kind === "text" && run && inT && !inRpr && !inPpr) {
      const reason = deleted ? "deleted" : field ? "field-code" : reasonOf();
      if (reason) c.hide(reason, t.text, part); else vis.push(t.text);
    }
  }
  c.visible(vis.join(""), `docx/${part}`);
}

export function extractDocx(zip: ZipRead): DocExtract {
  const c = new Collector("docx");
  const styles = docxStyles(text(zip.entries.get("word/styles.xml")));
  const order = (n: string) => (n === "word/document.xml" ? 0 : /header/.test(n) ? 1 : /footer/.test(n) ? 2 : 3);
  const parts = [...zip.entries.keys()].filter((n) => /^word\/(?:document|header\d*|footer\d*|footnotes|endnotes)\.xml$/.test(n)).sort((a, b) => order(a) - order(b) || a.localeCompare(b));
  if (!parts.includes("word/document.xml")) c.notes.push("word/document.xml is missing");
  for (const p of parts) { const xml = text(zip.entries.get(p)); docxBody(xml, p.replace(/^word\//, "").replace(/\.xml$/, ""), styles, c); altTexts(xml, c, p.replace(/^word\//, "")); }
  for (const p of [...zip.entries.keys()].filter((n) => /^word\/comments(?:Extended|Ids)?\d*\.xml$/.test(n) && !/Ids|Extended/.test(n))) c.other(allText(text(zip.entries.get(p))), "comment", `docx/comments`);
  common(zip, c, "word");
  return c.finish(zip);
}

// ---------- XLSX ----------

const colNum = (ref: string) => { const m = ref.match(/^([A-Z]+)/); let n = 0; for (const ch of m?.[1] ?? "") n = n * 26 + ch.charCodeAt(0) - 64; return n; };

export function extractXlsx(zip: ZipRead): DocExtract {
  const c = new Collector("xlsx");
  const wb = text(zip.entries.get("xl/workbook.xml"));
  const rels = new Map<string, string>();
  for (const m of text(zip.entries.get("xl/_rels/workbook.xml.rels")).matchAll(/<Relationship\b([^>]*)>/g)) { const id = attr(m[1], "Id"), tg = attr(m[1], "Target"); if (id && tg) rels.set(id, tg.replace(/^\/?xl\//, "").replace(/^\//, "")); }
  // shared strings
  const shared: string[] = [];
  { let cur: string[] | undefined, inPh = 0;
    for (const t of tokens(text(zip.entries.get("xl/sharedStrings.xml")))) {
      if (t.kind === "open" && t.local === "si" && !t.self) cur = [];
      else if (t.kind === "open" && t.local === "si" && t.self) shared.push("");
      else if (t.kind === "close" && t.local === "si") { shared.push((cur ?? []).join("")); cur = undefined; }
      else if (t.kind === "open" && t.local === "rPh" && !t.self) inPh++;
      else if (t.kind === "close" && t.local === "rPh") inPh--;
      else if (t.kind === "text" && cur && !inPh) cur.push(t.text);
    } }
  // styles: which cell formats show nothing, or in white or tiny type
  const styles = text(zip.entries.get("xl/styles.xml"));
  const blankFmt = new Set<string>();
  for (const m of styles.matchAll(/<numFmt\b([^>]*)\/?>/g)) { const code = attr(m[1], "formatCode") ?? ""; if (/^(?:;{2,3}|"";"";"";?"?"?)$/.test(code.replace(/\s/g, "")) || /^;;;(@?)$/.test(code)) blankFmt.add(attr(m[1], "numFmtId") ?? ""); }
  const fonts: Array<{ white: boolean; tiny: boolean }> = [];
  const fontsXml = styles.match(/<fonts\b[\s\S]*?<\/fonts>/)?.[0] ?? "";
  for (const m of fontsXml.matchAll(/<font\b[^>]*?(?:\/>|>([\s\S]*?)<\/font>)/g)) {
    const body = m[1] ?? "";
    const rgb = body.match(/<color\b[^>]*\brgb="([0-9A-Fa-f]{6,8})"/)?.[1];
    const theme = body.match(/<color\b[^>]*\btheme="(\d+)"/)?.[1];
    const sz = Number(body.match(/<sz\b[^>]*\bval="([\d.]+)"/)?.[1] ?? 11);
    fonts.push({ white: isWhite(rgb) || theme === "0", tiny: sz > 0 && sz < 2 });
  }
  const xfs: Array<{ blank: boolean; white: boolean; tiny: boolean }> = [];
  const cellXfs = styles.match(/<cellXfs\b[\s\S]*?<\/cellXfs>/)?.[0] ?? "";
  for (const m of cellXfs.matchAll(/<xf\b([^>]*)>/g)) { const f = fonts[Number(attr(m[1], "fontId") ?? 0)]; xfs.push({ blank: blankFmt.has(attr(m[1], "numFmtId") ?? "-"), white: !!f?.white, tiny: !!f?.tiny }); }

  const used = new Set<number>();
  let sheetIndex = 0;
  for (const m of wb.matchAll(/<(?:[\w]+:)?sheet\b([^>]*)\/?>/g)) {
    sheetIndex++;
    const name = attr(m[1], "name") ?? `sheet${sheetIndex}`, state = attr(m[1], "state") ?? "visible", rid = attr(m[1], "id");
    const target = rid ? rels.get(rid) : undefined;
    const xml = text(target ? zip.entries.get(`xl/${target}`) : undefined);
    if (!xml) { c.notes.push(`sheet "${name}" was not found in the file`); continue; }
    const sheetHidden = state === "veryHidden" ? "very-hidden-sheet" : state === "hidden" ? "hidden-sheet" : undefined;
    const hiddenCols: Array<[number, number]> = [];
    for (const cm of xml.matchAll(/<(?:[\w]+:)?col\b([^>]*)\/?>/g)) if (/\bhidden="(?:1|true)"/.test(cm[1])) hiddenCols.push([Number(attr(cm[1], "min")), Number(attr(cm[1], "max"))]);
    const lines: string[] = [];
    for (const rm of xml.matchAll(/<(?:[\w]+:)?row\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:[\w]+:)?row>)/g)) {
      const rowHidden = /\bhidden="(?:1|true)"/.test(rm[1]);
      const cells: string[] = [];
      for (const cmm of (rm[2] ?? "").matchAll(/<(?:[\w]+:)?c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:[\w]+:)?c>)/g)) {
        const a = cmm[1], body = cmm[2] ?? "", type = attr(a, "t"), ref = attr(a, "r") ?? "";
        let value = "";
        if (type === "s") { const i = Number(body.match(/<(?:[\w]+:)?v>(\d+)</)?.[1]); if (Number.isInteger(i)) { used.add(i); value = shared[i] ?? ""; } }
        else if (type === "inlineStr") value = [...body.matchAll(/<(?:[\w]+:)?t\b[^>]*>([^<]*)</g)].map((x) => xmlDecode(x[1])).join("");
        else if (type === "str" || type === "e") value = xmlDecode(body.match(/<(?:[\w]+:)?v>([^<]*)</)?.[1] ?? "");
        else continue; // numbers, dates and booleans say nothing
        if (!value.trim()) continue;
        const xf = xfs[Number(attr(a, "s") ?? 0)];
        const col = colNum(ref);
        const reason = sheetHidden ?? (rowHidden ? "hidden-row" : hiddenCols.some(([lo, hi]) => col >= lo && col <= hi) ? "hidden-column" : xf?.blank ? "blank-format" : xf?.tiny ? "tiny" : xf?.white ? "white" : undefined);
        if (reason) c.hide(reason, value, `sheet "${name}"${ref ? ` ${ref}` : ""}`); else cells.push(value);
      }
      if (cells.length) lines.push(cells.join("\t"));
    }
    if (lines.length) c.visible(lines.join("\n"), `xlsx/sheet:${name}`);
    altTexts(text(zip.entries.get(`xl/drawings/drawing${sheetIndex}.xml`)), c, `sheet ${name}`);
  }
  shared.forEach((s, i) => { if (!used.has(i) && s.trim()) c.hide("unused-string", s, "sharedStrings.xml"); });
  for (const [n, d] of zip.entries) if (/^xl\/(?:comments\d*|threadedComments\/[^/]+)\.xml$/.test(n)) c.other(allText(text(d)), "comment", "xlsx/comments");
  for (const [n, d] of zip.entries) if (/^xl\/drawings\/drawing\d+\.xml$/.test(n)) { /* alt text read per sheet above; any drawing not tied to a sheet */ if (!c.segments.some((s) => s.path.includes("alt-text"))) altTexts(text(d), c, n.split("/").pop()!); }
  common(zip, c, "xl");
  return c.finish(zip);
}

// ---------- PPTX ----------

export function extractPptx(zip: ZipRead): DocExtract {
  const c = new Collector("pptx");
  const pres = text(zip.entries.get("ppt/presentation.xml"));
  const sz = pres.match(/<(?:[\w]+:)?sldSz\b([^>]*)>/)?.[1] ?? "";
  const W = Number(attr(sz, "cx") ?? 12_192_000), H = Number(attr(sz, "cy") ?? 6_858_000);
  const num = (n: string) => Number(n.match(/(\d+)\.xml$/)?.[1] ?? 0);
  const slides = [...zip.entries.keys()].filter((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n)).sort((a, b) => num(a) - num(b));
  for (const p of slides) {
    const xml = text(zip.entries.get(p));
    const where = `slide ${num(p)}`;
    const vis: string[] = [];
    // one shape at a time: its own visibility, then each run's formatting
    let shapeDepth = 0, shapeReason: string | undefined, inXfrm = false, off: [number, number] | undefined;
    let run: { sz?: number; white?: boolean } | undefined, inRpr = false, rprDepth = 0, depth = 0;
    const stack: string[] = [];
    for (const t of tokens(xml)) {
      if (t.kind === "open") {
        if (!t.self) { stack.push(t.local); depth++; }
        if ((t.local === "sp" || t.local === "pic" || t.local === "graphicFrame" || t.local === "cxnSp") && !t.self) { shapeDepth = depth; shapeReason = undefined; off = undefined; }
        else if (t.local === "cNvPr" && shapeDepth && /\bhidden="(?:1|true)"/.test(t.attrs)) shapeReason = "hidden-shape";
        else if (t.local === "xfrm" && shapeDepth && !t.self) inXfrm = true;
        else if (inXfrm && t.local === "off") off = [Number(attr(t.attrs, "x") ?? 0), Number(attr(t.attrs, "y") ?? 0)];
        else if (inXfrm && t.local === "ext" && off && !shapeReason) {
          const cx = Number(attr(t.attrs, "cx") ?? 0), cy = Number(attr(t.attrs, "cy") ?? 0);
          if (off[0] >= W || off[1] >= H || off[0] + cx <= 0 || off[1] + cy <= 0) shapeReason = "off-slide";
        }
        else if (t.local === "r" && !t.self) run = {};
        else if (t.local === "rPr" && run) { const s = Number(attr(t.attrs, "sz") ?? 0); if (s > 0) run.sz = s; if (!t.self) { inRpr = true; rprDepth = depth; } }
        else if (inRpr && (t.local === "srgbClr" || t.local === "schemeClr" || t.local === "sysClr") && stack[stack.length - (t.self ? 1 : 2)] === "solidFill" && stack[stack.length - (t.self ? 2 : 3)] === "rPr") {
          const v = attr(t.attrs, t.local === "sysClr" ? "lastClr" : "val");
          if (run) run.white = t.local === "schemeClr" ? /^(?:bg1|lt1)$/.test(v ?? "") : isWhite(v);
        }
        else if (t.local === "br" && t.self) vis.push("\n");
      } else if (t.kind === "close") {
        if (t.local === "xfrm") inXfrm = false;
        if (t.local === "rPr" && depth === rprDepth) inRpr = false;
        if (t.local === "r") run = undefined;
        if (t.local === "p") vis.push("\n");
        if (depth === shapeDepth && /^(?:sp|pic|graphicFrame|cxnSp)$/.test(t.local)) { shapeDepth = 0; shapeReason = undefined; }
        stack.pop(); depth--;
      } else if (t.kind === "text" && run && !inRpr && stack[stack.length - 1] === "t") {
        const reason = shapeReason ?? (run.sz !== undefined && run.sz < 200 ? "tiny" : run.white ? "white" : undefined);
        if (reason) c.hide(reason, t.text, where); else vis.push(t.text);
      }
    }
    c.visible(vis.join(""), `pptx/${where.replace(" ", "")}`);
    altTexts(xml, c, where);
  }
  for (const [n, d] of [...zip.entries].sort((a, b) => num(a[0]) - num(b[0]))) {
    if (/^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(n)) { const t = allText(text(d)); if (words(t) >= 1) c.other(t, "comment", `pptx/notes:slide${num(n)}`); }
    else if (/^ppt\/comments\/.+\.xml$/.test(n)) c.other(allText(text(d)), "comment", "pptx/comments");
  }
  common(zip, c, "ppt");
  return c.finish(zip);
}

/** which Office format a ZIP is, from its parts */
export function officeKind(zip: ZipRead): "docx" | "xlsx" | "pptx" | undefined {
  if (zip.entries.has("word/document.xml")) return "docx";
  if (zip.entries.has("xl/workbook.xml")) return "xlsx";
  if (zip.entries.has("ppt/presentation.xml")) return "pptx";
  const ct = text(zip.entries.get("[Content_Types].xml"));
  if (/wordprocessingml/.test(ct)) return "docx";
  if (/spreadsheetml/.test(ct)) return "xlsx";
  if (/presentationml/.test(ct)) return "pptx";
  return undefined;
}

export function extractOffice(bytes: Uint8Array): DocExtract | undefined {
  const zip = readZip(bytes);
  const kind = officeKind(zip);
  if (kind === "docx") return extractDocx(zip);
  if (kind === "xlsx") return extractXlsx(zip);
  if (kind === "pptx") return extractPptx(zip);
  return undefined;
}
