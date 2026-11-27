/**
 * PDF: what a person sees on the page, and what only a text extractor sees.
 *
 * An agent that "reads a PDF" reads its text layer. The text layer holds everything the file draws, and also
 * text the file draws in a way no person can see: white on white, under 2 points, outside the page, in the
 * invisible render mode (Tr 3), behind a filled shape, at zero opacity, in a layer that is switched off. It
 * also holds text that is never drawn at all: annotations, form fields, document info and XMP metadata,
 * JavaScript. This module separates the two, without rendering, by following the drawing instructions.
 *
 * A minimal parser, written here with no dependency (pdf.js is ~30 MB unpacked; this is one file). It reads:
 * objects (also inside object streams), Flate/ASCIIHex/ASCII85 streams, the page tree with inherited
 * resources and boxes, content streams and form XObjects, simple fonts and ToUnicode maps, ExtGState fill
 * opacity, optional content (layers switched off by default), annotations, form fields, the Info dictionary,
 * XMP, and JavaScript / OpenAction / Launch / embedded files.
 *
 * Limits, stated plainly: encrypted files are not decrypted (reported, not read); LZW, CCITT, JBIG2, DCT and
 * JPX streams are not decoded (text is never in the latter four); word spacing comes from glyph widths and gaps,
 * so it is close but not exact; fonts without a ToUnicode map and with a custom /Differences encoding may decode to the
 * wrong letters; text drawn inside images (scans) needs OCR, which this does not do; clipping paths and
 * shapes other than rectangles are not used to decide what covers what; text covered by an image is not
 * detected; shapes drawn with a soft mask, a blend mode or in a transparency group are not counted as covering;
 * the page background is assumed white unless a filled rectangle says otherwise.
 */
import { inflateSync } from "node:zlib";
import { xmpTexts } from "./image-meta.js";
import type { Finding, TextSegment } from "./types.js";
import type { DocExtract } from "./filescan.js";

// ---------- values ----------

type Name = { t: "name"; v: string };
type Str = { t: "str"; v: string /* latin1 bytes */ };
type Ref = { t: "ref"; n: number; g: number };
type Dict = { t: "dict"; m: Record<string, PV>; stream?: string /* raw bytes, latin1 */ };
type Op = { t: "op"; v: string };
type PV = number | boolean | null | Name | Str | Ref | Dict | PV[];

const isName = (x: unknown): x is Name => !!x && typeof x === "object" && (x as Name).t === "name";
const isStr = (x: unknown): x is Str => !!x && typeof x === "object" && (x as Str).t === "str";
const isRef = (x: unknown): x is Ref => !!x && typeof x === "object" && (x as Ref).t === "ref";
const isDict = (x: unknown): x is Dict => !!x && typeof x === "object" && (x as Dict).t === "dict";

const WS = new Set([0, 9, 10, 12, 13, 32]);
const DELIM = new Set("()<>[]{}/%".split("").map((c) => c.charCodeAt(0)));

class Lexer {
  constructor(public s: string, public p = 0) {}
  skip(): void {
    const s = this.s;
    while (this.p < s.length) {
      const c = s.charCodeAt(this.p);
      if (WS.has(c)) this.p++;
      else if (c === 37) { while (this.p < s.length && s[this.p] !== "\n" && s[this.p] !== "\r") this.p++; }
      else break;
    }
  }
  /** the next token: a value, an operator/keyword, or a structural mark */
  next(): PV | Op | { t: "mark"; v: string } | undefined {
    this.skip();
    const s = this.s;
    if (this.p >= s.length) return undefined;
    const c = s[this.p];
    if (c === "/") {
      let q = this.p + 1;
      while (q < s.length && !WS.has(s.charCodeAt(q)) && !DELIM.has(s.charCodeAt(q))) q++;
      const raw = s.slice(this.p + 1, q); this.p = q;
      return { t: "name", v: raw.replace(/#([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) };
    }
    if (c === "(") return this.literal();
    if (c === "<") {
      if (s[this.p + 1] === "<") { this.p += 2; return { t: "mark", v: "<<" }; }
      const q = s.indexOf(">", this.p);
      const hex = s.slice(this.p + 1, q < 0 ? s.length : q).replace(/[^0-9a-fA-F]/g, "");
      this.p = q < 0 ? s.length : q + 1;
      let out = "";
      for (let i = 0; i < hex.length; i += 2) out += String.fromCharCode(parseInt((hex[i] + (hex[i + 1] ?? "0")), 16));
      return { t: "str", v: out };
    }
    if (c === ">" && s[this.p + 1] === ">") { this.p += 2; return { t: "mark", v: ">>" }; }
    if (c === "[" || c === "]" || c === "{" || c === "}") { this.p++; return { t: "mark", v: c }; }
    let q = this.p;
    while (q < s.length && !WS.has(s.charCodeAt(q)) && !DELIM.has(s.charCodeAt(q))) q++;
    if (q === this.p) { this.p++; return { t: "op", v: c }; }
    const w = s.slice(this.p, q); this.p = q;
    if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(w)) return Number(w);
    if (w === "true") return true;
    if (w === "false") return false;
    if (w === "null") return null;
    return { t: "op", v: w };
  }
  literal(): Str {
    const s = this.s;
    let depth = 0, out = "", i = this.p;
    for (; i < s.length; i++) {
      const c = s[i];
      if (c === "(") { if (depth++ > 0) out += c; continue; }
      if (c === ")") { if (--depth === 0) { i++; break; } out += c; continue; }
      if (c === "\\") {
        const d = s[++i];
        if (d === "n") out += "\n"; else if (d === "r") out += "\r"; else if (d === "t") out += "\t"; else if (d === "b") out += "\b"; else if (d === "f") out += "\f";
        else if (d === "\r") { if (s[i + 1] === "\n") i++; }
        else if (d === "\n") { /* line continuation */ }
        else if (d >= "0" && d <= "7") { let o = d; while (o.length < 3 && s[i + 1] >= "0" && s[i + 1] <= "7") o += s[++i]; out += String.fromCharCode(parseInt(o, 8) & 0xff); }
        else if (d !== undefined) out += d;
        continue;
      }
      out += c;
    }
    this.p = i;
    return { t: "str", v: out };
  }
}

/** parse one value (with "n g R" references) from a lexer; operators come back as Op */
function parseValue(lx: Lexer, depth = 0): PV | Op | undefined {
  const tok = lx.next();
  if (tok === undefined) return undefined;
  if (typeof tok === "object" && tok !== null && (tok as { t: string }).t === "mark") {
    const m = (tok as { v: string }).v;
    if (depth > 64) return null;
    if (m === "[") {
      const arr: PV[] = [];
      for (let guard = 0; guard < 1_000_000; guard++) {
        const save = lx.p; const t = lx.next();
        if (t === undefined) break;
        if (typeof t === "object" && t !== null && (t as { t: string }).t === "mark" && (t as { v: string }).v === "]") break;
        lx.p = save;
        const v = parseValue(lx, depth + 1);
        if (v === undefined) break;
        if (typeof v === "object" && v !== null && (v as Op).t === "op") {
          if ((v as Op).v === "R" && arr.length >= 2 && typeof arr[arr.length - 1] === "number" && typeof arr[arr.length - 2] === "number") {
            const g = arr.pop() as number, n = arr.pop() as number; arr.push({ t: "ref", n, g });
          }
          continue;
        }
        arr.push(v as PV);
      }
      return arr;
    }
    if (m === "<<") {
      const d: Dict = { t: "dict", m: {} };
      for (let guard = 0; guard < 100_000; guard++) {
        const save = lx.p; const k = lx.next();
        if (k === undefined) break;
        if (typeof k === "object" && k !== null && (k as { t: string }).t === "mark" && (k as { v: string }).v === ">>") break;
        if (!isName(k)) { if (lx.p === save) lx.p++; continue; }
        const v = parseValue(lx, depth + 1);
        if (v === undefined) break;
        if (typeof v === "object" && v !== null && (v as Op).t === "op") continue;
        // a reference: n g R
        if (typeof v === "number") {
          const save2 = lx.p; const g = lx.next(); const r = lx.next();
          if (typeof g === "number" && r && (r as Op).t === "op" && (r as Op).v === "R") { d.m[k.v] = { t: "ref", n: v, g }; continue; }
          lx.p = save2;
        }
        d.m[k.v] = v as PV;
      }
      return d;
    }
    return null;
  }
  return tok as PV | Op;
}

// ---------- streams ----------

const MAX_STREAM = 64_000_000;

function ascii85(s: string): string {
  let out = "", tuple = 0, n = 0;
  const body = s.replace(/^\s*<~/, "").split("~>")[0];
  for (const ch of body) {
    if (/\s/.test(ch)) continue;
    if (ch === "z" && n === 0) { out += "\0\0\0\0"; continue; }
    const c = ch.charCodeAt(0) - 33;
    if (c < 0 || c > 84) continue;
    tuple = tuple * 85 + c; n++;
    if (n === 5) { out += String.fromCharCode((tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255); tuple = 0; n = 0; }
  }
  if (n > 1) { for (let i = n; i < 5; i++) tuple = tuple * 85 + 84; const b = [(tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255]; out += String.fromCharCode(...b.slice(0, n - 1)); }
  return out;
}

class Pdf {
  objs = new Map<number, PV>();
  notes: string[] = [];
  encrypted = false;
  private streamCache = new Map<Dict, string | null>();
  decodedBytes = 0;
  constructor(public s: string) {}

  resolve(v: PV | undefined, depth = 0): PV | undefined {
    while (isRef(v) && depth++ < 32) v = this.objs.get(v.n);
    return v;
  }
  dict(v: PV | undefined): Dict | undefined { const r = this.resolve(v); return isDict(r) ? r : undefined; }
  get(d: Dict | undefined, k: string): PV | undefined { return d ? this.resolve(d.m[k]) : undefined; }
  num(v: PV | undefined): number | undefined { const r = this.resolve(v); return typeof r === "number" ? r : undefined; }

  /** the decoded bytes of a stream (latin1), or null when its filter is not supported */
  data(d: Dict): string | null {
    if (this.streamCache.has(d)) return this.streamCache.get(d)!;
    let out: string | null = d.stream ?? "";
    const f = this.resolve(d.m.Filter);
    const filters = (Array.isArray(f) ? f : f ? [f] : []).map((x) => (isName(x) ? x.v : ""));
    for (const name of filters) {
      if (out === null) break;
      try {
        if (name === "FlateDecode" || name === "Fl") {
          const buf = inflateSync(Buffer.from(out, "latin1"), { maxOutputLength: Math.max(1, MAX_STREAM - this.decodedBytes), finishFlush: 2 /* Z_SYNC_FLUSH: tolerate a missing end */ });
          out = buf.toString("latin1");
        } else if (name === "ASCIIHexDecode" || name === "AHx") {
          const hex = out.replace(/>.*$/s, "").replace(/[^0-9a-fA-F]/g, "");
          let o = ""; for (let i = 0; i < hex.length; i += 2) o += String.fromCharCode(parseInt(hex[i] + (hex[i + 1] ?? "0"), 16)); out = o;
        } else if (name === "ASCII85Decode" || name === "A85") out = ascii85(out);
        else { this.notes.push(`a stream uses the ${name} filter, which is not decoded`); out = null; }
      } catch (e) { this.notes.push(`a stream could not be decoded (${(e as Error).message.slice(0, 60)})`); out = null; }
    }
    if (out !== null) this.decodedBytes += out.length;
    this.streamCache.set(d, out);
    return out;
  }

  load(): void {
    const s = this.s;
    const re = /(\d+)\s+(\d+)\s+obj\b/g;
    let m: RegExpExecArray | null, count = 0;
    while ((m = re.exec(s)) && count++ < 500_000) {
      const lx = new Lexer(s, m.index + m[0].length);
      const v = parseValue(lx);
      if (v === undefined || (typeof v === "object" && v !== null && (v as Op).t === "op")) continue;
      if (isDict(v)) {
        const save = lx.p; const t = lx.next();
        if (t && (t as Op).t === "op" && (t as Op).v === "stream") {
          let start = lx.p;
          // the keyword is followed by CRLF or LF
          start = s.indexOf("stream", save) + 6;
          if (s[start] === "\r") start++;
          if (s[start] === "\n") start++;
          const len = typeof v.m.Length === "number" ? v.m.Length : undefined;
          let end = len !== undefined && s.slice(start + len, start + len + 30).includes("endstream") ? start + len : s.indexOf("endstream", start);
          if (end < 0) end = s.length;
          v.stream = s.slice(start, end).replace(/\r?\n$/, len !== undefined ? "$&" : "");
          re.lastIndex = end;
        } else lx.p = save;
      }
      this.objs.set(Number(m[1]), v as PV); // a later definition (an incremental update) replaces an earlier one
    }
    // a length given as a reference can only be read now
    for (const v of this.objs.values()) {
      if (isDict(v) && v.stream !== undefined && isRef(v.m.Length)) {
        const len = this.num(v.m.Length);
        if (len !== undefined && len < v.stream.length) v.stream = v.stream.slice(0, len);
      }
    }
    // objects inside object streams fill the numbers not defined directly
    for (const v of [...this.objs.values()]) {
      if (!isDict(v) || !isName(v.m.Type) || v.m.Type.v !== "ObjStm") continue;
      const data = this.data(v); if (data === null) continue;
      const n = this.num(v.m.N) ?? 0, first = this.num(v.m.First) ?? 0;
      const head = new Lexer(data);
      const pairs: Array<[number, number]> = [];
      for (let i = 0; i < n && i < 100_000; i++) { const a = head.next(), b = head.next(); if (typeof a === "number" && typeof b === "number") pairs.push([a, b]); }
      for (const [num, off] of pairs) {
        if (this.objs.has(num)) continue;
        const val = parseValue(new Lexer(data, first + off));
        if (val !== undefined && !(typeof val === "object" && val !== null && (val as Op).t === "op")) this.objs.set(num, val as PV);
      }
    }
    if (/\/Encrypt\s+(?:\d+\s+\d+\s+R|<<)/.test(s)) this.encrypted = true;
  }
}

// ---------- text decoding ----------

interface Font { codeLen: number; map?: Map<string, string>; /** glyph widths in thousandths of an em, by code */ widths?: Map<number, number>; dw?: number }

function parseCmap(cmap: string): Font {
  const map = new Map<string, string>();
  let codeLen = 0;
  const hexToStr = (h: string) => { let o = ""; for (let i = 0; i + 1 < h.length; i += 2) o += String.fromCharCode(parseInt(h.slice(i, i + 2), 16)); return o; };
  const utf16 = (h: string) => { let o = ""; for (let i = 0; i + 3 < h.length; i += 4) o += String.fromCharCode(parseInt(h.slice(i, i + 4), 16)); return o; };
  for (const block of cmap.matchAll(/begincodespacerange([\s\S]*?)endcodespacerange/g)) {
    const m = block[1].match(/<([0-9a-fA-F]+)>/); if (m && !codeLen) codeLen = m[1].length / 2;
  }
  for (const block of cmap.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const m of block[1].matchAll(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]*)>/g)) { map.set(hexToStr(m[1]), utf16(m[2])); if (!codeLen) codeLen = m[1].length / 2; }
  }
  for (const block of cmap.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const m of block[1].matchAll(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*(?:<([0-9a-fA-F]*)>|\[([^\]]*)\])/g)) {
      const lo = parseInt(m[1], 16), hi = Math.min(parseInt(m[2], 16), lo + 65_535), w = m[1].length;
      if (!codeLen) codeLen = w / 2;
      const list = m[4] ? [...m[4].matchAll(/<([0-9a-fA-F]*)>/g)].map((x) => x[1]) : undefined;
      for (let c = lo; c <= hi; c++) {
        const key = hexToStr(c.toString(16).padStart(w, "0"));
        if (list) { const d = list[c - lo]; if (d !== undefined) map.set(key, utf16(d)); }
        else if (m[3] !== undefined) {
          const base = m[3];
          const last = parseInt(base.slice(-4) || "0", 16) + (c - lo);
          map.set(key, utf16(base.slice(0, -4) + last.toString(16).padStart(4, "0")));
        }
      }
    }
  }
  return { codeLen: codeLen || 1, map };
}

function decodeText(bytes: string, font: Font | undefined): string {
  if (!font?.map) {
    if ((font?.codeLen ?? 1) === 2) return ""; // a two-byte font without a map: the codes are glyph numbers
    return bytes.replace(/[\0-\x08\x0b\x0e-\x1f]/g, "");
  }
  let out = "";
  for (let i = 0; i < bytes.length; i += font.codeLen) {
    const code = bytes.slice(i, i + font.codeLen);
    out += font.map.get(code) ?? (font.codeLen === 1 ? code : "");
  }
  return out;
}

// ---------- drawing ----------

type M = [number, number, number, number, number, number];
const I: M = [1, 0, 0, 1, 0, 0];
const mul = (A: M, B: M): M => [A[0] * B[0] + A[1] * B[2], A[0] * B[1] + A[1] * B[3], A[2] * B[0] + A[3] * B[2], A[2] * B[1] + A[3] * B[3], A[4] * B[0] + A[5] * B[2] + B[4], A[4] * B[1] + A[5] * B[3] + B[5]];
const apply = (m: M, x: number, y: number): [number, number] => [x * m[0] + y * m[2] + m[4], x * m[1] + y * m[3] + m[5]];
type RGB = [number, number, number];
const colorOf = (ops: number[]): RGB => ops.length >= 4 ? [(1 - ops[0]) * (1 - ops[3]), (1 - ops[1]) * (1 - ops[3]), (1 - ops[2]) * (1 - ops[3])] : ops.length === 3 ? [ops[0], ops[1], ops[2]] : ops.length >= 1 ? [ops[0], ops[0], ops[0]] : [0, 0, 0];
const close = (a: RGB, b: RGB) => Math.max(Math.abs(a[0] - b[0]), Math.abs(a[1] - b[1]), Math.abs(a[2] - b[2])) < 0.06;

interface GState { ctm: M; fill: RGB; stroke: RGB; fillAlpha: number; /** a blend mode other than Normal (Multiply, a highlighter) does not cover what is under it */ blend: boolean; font?: Font; fontSize: number; tr: number; th: number; tc: number; tw: number; tl: number; rise: number }
interface Run { text: string; page: number; x: number; y: number; endX: number; size: number; order: number; reasons: string[]; /** the box the glyphs occupy, on the page (rotated text included) */ box: [number, number, number, number] }
interface FillRect { x0: number; y0: number; x1: number; y1: number; color: RGB; alpha: number; order: number }

/** why a run cannot be seen: the label is shown to the person, the key groups runs */
export const PDF_HIDDEN: Record<string, { label: string; visibility: TextSegment["visibility"] }> = {
  "render-invisible": { label: "drawn in the invisible text mode (Tr 3)", visibility: "concealed" },
  "background-colour": { label: "in the background colour (for example white on white)", visibility: "tiny_or_transparent" },
  transparent: { label: "at zero opacity", visibility: "tiny_or_transparent" },
  tiny: { label: "under 2 points tall", visibility: "tiny_or_transparent" },
  squeezed: { label: "squeezed to almost no width", visibility: "tiny_or_transparent" },
  "off-page": { label: "outside the page", visibility: "offscreen" },
  covered: { label: "covered by a filled shape drawn on top", visibility: "concealed" },
  "layer-off": { label: "in a layer that is switched off", visibility: "concealed" },
};

const MAX_OPS = 2_000_000, MAX_RUNS = 200_000;

function drawPage(pdf: Pdf, content: string, resources: Dict | undefined, box: number[], page: number, offLayers: Set<number>, runs: Run[], fills: FillRect[], fontCache: Map<unknown, Font>, counter: { order: number; ops: number }, depth = 0, init?: GState, inOffLayer = false): void {
  const lx = new Lexer(content);
  const stack: GState[] = [];
  // a form XObject draws with the state it was called in (colour, opacity, font); a page starts from the defaults
  let gs: GState = init ? { ...init } : { ctm: I, fill: [0, 0, 0], stroke: [0, 0, 0], fillAlpha: 1, blend: false, fontSize: 0, tr: 0, th: 1, tc: 0, tw: 0, tl: 0, rise: 0 };
  let tm: M = I, tlm: M = I;
  let ops: Array<PV> = [];
  let pathRects: Array<[number, number, number, number]> = [];
  const marked: boolean[] = inOffLayer ? [true] : []; // true when that marked-content level is a switched-off layer
  const fontFor = (name: string): Font | undefined => {
    const ref = pdf.dict(pdf.get(resources, "Font"))?.m[name];
    const key = isRef(ref) ? `${ref.n}` : ref;
    if (key !== undefined && fontCache.has(key)) return fontCache.get(key);
    const fd = pdf.dict(ref);
    if (!fd) return undefined;
    const type0 = isName(fd.m.Subtype) && fd.m.Subtype.v === "Type0";
    let font: Font = { codeLen: type0 ? 2 : 1 };
    const tu = pdf.dict(fd.m.ToUnicode);
    if (tu) { const d = pdf.data(tu); if (d) { const c = parseCmap(d); font = { codeLen: type0 ? Math.max(2, c.codeLen) : c.codeLen, map: c.map }; } }
    // glyph widths, so the gaps between words can be told from the gaps between letters
    const widths = new Map<number, number>();
    if (type0) {
      const desc = pdf.resolve(fd.m.DescendantFonts);
      const cid = pdf.dict(Array.isArray(desc) ? desc[0] : undefined);
      font.dw = pdf.num(cid?.m.DW) ?? 1000;
      const w = pdf.resolve(cid?.m.W);
      if (Array.isArray(w)) for (let i = 0; i < w.length && widths.size < 70_000;) {
        const a = pdf.num(w[i]); const b = pdf.resolve(w[i + 1]);
        if (a === undefined) break;
        if (Array.isArray(b)) { b.forEach((x, k) => { const n = pdf.num(x); if (n !== undefined) widths.set(a + k, n); }); i += 2; }
        else { const hi = pdf.num(b), n = pdf.num(w[i + 2]); if (hi === undefined || n === undefined) break; for (let c = a; c <= Math.min(hi, a + 65_535); c++) widths.set(c, n); i += 3; }
      }
    } else {
      const first = pdf.num(fd.m.FirstChar) ?? 0;
      const w = pdf.resolve(fd.m.Widths);
      if (Array.isArray(w)) w.forEach((x, k) => { const n = pdf.num(x); if (n !== undefined) widths.set(first + k, n); });
      font.dw = pdf.num(pdf.dict(fd.m.FontDescriptor)?.m.MissingWidth) || 500;
    }
    if (widths.size) font.widths = widths;
    if (key !== undefined) fontCache.set(key, font);
    return font;
  };
  const show = (str: string, lead = "") => {
    if (runs.length >= MAX_RUNS) return;
    const decoded = decodeText(str, gs.font);
    const text = decoded ? lead + decoded : "";
    const trm = mul(tm, gs.ctm);
    const size = gs.fontSize * Math.hypot(trm[2], trm[3]);
    const [x, y] = apply(trm, 0, gs.rise);
    // the pen moves by each glyph's width (half an em when the font gives none)
    const cl = gs.font?.codeLen ?? 1;
    let em = 0, n = 0, spaces = 0;
    for (let i = 0; i + cl <= str.length; i += cl) {
      const code = cl === 2 ? (str.charCodeAt(i) << 8) | str.charCodeAt(i + 1) : str.charCodeAt(i);
      em += (gs.font?.widths?.get(code) ?? (gs.font?.widths ? gs.font.dw ?? 500 : 500)) / 1000;
      n++; if (cl === 1 && code === 32) spaces++;
    }
    const tx = (em * gs.fontSize + gs.tc * n + gs.tw * spaces) * gs.th;
    const top = apply(trm, 0, gs.rise + gs.fontSize * 0.7);
    tm = mul([1, 0, 0, 1, tx, 0], tm);
    const [endX, endY] = apply(mul(tm, gs.ctm), 0, gs.rise);
    const xs = [x, endX, top[0], endX + top[0] - x], ys = [y, endY, top[1], endY + top[1] - y];
    const glyphs: Run["box"] = [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)];
    if (!text) return;
    const reasons: string[] = [];
    if (gs.tr === 3 || gs.tr === 7) reasons.push("render-invisible");
    if (marked.some(Boolean)) reasons.push("layer-off");
    if (gs.fillAlpha <= 0.02 && gs.tr !== 1 && gs.tr !== 5) reasons.push("transparent");
    if (size > 0 && size < 2) reasons.push("tiny");
    if (gs.th * Math.hypot(trm[0], trm[1]) / Math.max(1e-9, Math.hypot(trm[2], trm[3])) < 0.1) reasons.push("squeezed");
    const [bx0, by0, bx1, by1] = box;
    if (x < bx0 - 2 || x > bx1 + 2 || y < by0 - 2 || y > by1 + 2) reasons.push("off-page");
    // the colour behind the text: the last filled rectangle under its start, else the paper
    let bg: RGB = [1, 1, 1];
    for (let i = fills.length - 1; i >= 0; i--) { const f = fills[i]; if (f.alpha > 0.9 && x >= f.x0 && x <= f.x1 && y >= f.y0 && y <= f.y1) { bg = f.color; break; } }
    const ink = gs.tr === 1 || gs.tr === 5 ? gs.stroke : gs.fill;
    if (!reasons.includes("render-invisible") && close(ink, bg)) reasons.push("background-colour");
    runs.push({ text, page, x, y, endX, size, order: counter.order++, reasons, box: glyphs });
  };
  for (;;) {
    if (counter.ops++ > MAX_OPS) { pdf.notes.push(`page ${page}: stopped after ${MAX_OPS} drawing operations`); return; }
    const v = parseValue(lx);
    if (v === undefined) break;
    if (!(typeof v === "object" && v !== null && (v as Op).t === "op")) { ops.push(v as PV); if (ops.length > 10_000) ops = ops.slice(-100); continue; }
    const op = (v as Op).v;
    const nums = ops.filter((x): x is number => typeof x === "number");
    switch (op) {
      case "q": stack.push({ ...gs }); if (stack.length > 256) stack.shift(); break;
      case "Q": gs = stack.pop() ?? gs; break;
      case "cm": if (nums.length >= 6) gs.ctm = mul(nums.slice(-6) as M, gs.ctm); break;
      case "BT": tm = I; tlm = I; break;
      case "ET": break;
      case "Tf": { const n = ops[ops.length - 2]; if (isName(n)) gs.font = fontFor(n.v); gs.fontSize = nums[nums.length - 1] ?? gs.fontSize; break; }
      case "Tr": gs.tr = nums[nums.length - 1] ?? 0; break;
      case "Tz": gs.th = (nums[nums.length - 1] ?? 100) / 100; break;
      case "Tc": gs.tc = nums[nums.length - 1] ?? 0; break;
      case "Tw": gs.tw = nums[nums.length - 1] ?? 0; break;
      case "TL": gs.tl = nums[nums.length - 1] ?? 0; break;
      case "Ts": gs.rise = nums[nums.length - 1] ?? 0; break;
      case "Td": case "TD": if (nums.length >= 2) { const [tx, ty] = nums.slice(-2); if (op === "TD") gs.tl = -ty; tlm = mul([1, 0, 0, 1, tx, ty], tlm); tm = tlm; } break;
      case "Tm": if (nums.length >= 6) { tlm = nums.slice(-6) as M; tm = tlm; } break;
      case "T*": tlm = mul([1, 0, 0, 1, 0, -gs.tl], tlm); tm = tlm; break;
      case "Tj": { const s = ops[ops.length - 1]; if (isStr(s)) show(s.v); break; }
      case "'": { tlm = mul([1, 0, 0, 1, 0, -gs.tl], tlm); tm = tlm; const s = ops[ops.length - 1]; if (isStr(s)) show(s.v); break; }
      case "\"": { if (nums.length >= 2) { gs.tw = nums[nums.length - 2]; gs.tc = nums[nums.length - 1]; } tlm = mul([1, 0, 0, 1, 0, -gs.tl], tlm); tm = tlm; const s = ops[ops.length - 1]; if (isStr(s)) show(s.v); break; }
      case "TJ": {
        const arr = ops[ops.length - 1];
        if (Array.isArray(arr)) {
          let lead = "";
          for (const part of arr) {
            // a number moves the pen back (positive) or on (negative), in thousandths of the font size
            if (typeof part === "number") { tm = mul([1, 0, 0, 1, (-part / 1000) * gs.fontSize * gs.th, 0], tm); if (part < -180) lead = " "; continue; }
            if (isStr(part)) { show(part.v, lead); lead = ""; }
          }
        }
        break;
      }
      case "g": gs.fill = colorOf(nums.slice(-1)); break;
      case "G": gs.stroke = colorOf(nums.slice(-1)); break;
      case "rg": gs.fill = colorOf(nums.slice(-3)); break;
      case "RG": gs.stroke = colorOf(nums.slice(-3)); break;
      case "k": gs.fill = colorOf(nums.slice(-4)); break;
      case "K": gs.stroke = colorOf(nums.slice(-4)); break;
      case "sc": case "scn": if (nums.length && !isName(ops[ops.length - 1])) gs.fill = colorOf(nums.length >= 4 ? nums.slice(-4) : nums.length === 3 ? nums.slice(-3) : nums.slice(-1)); break;
      case "SC": case "SCN": if (nums.length && !isName(ops[ops.length - 1])) gs.stroke = colorOf(nums.length >= 4 ? nums.slice(-4) : nums.length === 3 ? nums.slice(-3) : nums.slice(-1)); break;
      case "cs": gs.fill = [0, 0, 0]; break;
      case "CS": gs.stroke = [0, 0, 0]; break;
      case "gs": {
        const n = ops[ops.length - 1];
        if (isName(n)) { const eg = pdf.dict(pdf.dict(pdf.get(resources, "ExtGState"))?.m[n.v]); const ca = pdf.num(eg?.m.ca); if (ca !== undefined) gs.fillAlpha = ca;
          const bm = pdf.resolve(eg?.m.BM); const bmName = isName(bm) ? bm.v : Array.isArray(bm) && isName(bm[0]) ? bm[0].v : undefined;
          if (bmName !== undefined) gs.blend = !/^(?:Normal|Compatible)$/.test(bmName);
          // a soft mask makes what is drawn partly see-through: it is not counted as covering
          const sm = pdf.resolve(eg?.m.SMask); if (sm !== undefined && !(isName(sm) && sm.v === "None")) gs.blend = true; }
        break;
      }
      case "re": if (nums.length >= 4) {
        const [x, y, w, h] = nums.slice(-4);
        const pts = [apply(gs.ctm, x, y), apply(gs.ctm, x + w, y), apply(gs.ctm, x, y + h), apply(gs.ctm, x + w, y + h)];
        pathRects.push([Math.min(...pts.map((p) => p[0])), Math.min(...pts.map((p) => p[1])), Math.max(...pts.map((p) => p[0])), Math.max(...pts.map((p) => p[1]))]);
      } break;
      case "f": case "F": case "f*": case "B": case "B*": case "b": case "b*":
        for (const [x0, y0, x1, y1] of pathRects) {
          const r: FillRect = { x0, y0, x1, y1, color: gs.fill, alpha: gs.blend ? 0 : gs.fillAlpha, order: counter.order++ };
          fills.push(r);
          // text drawn earlier under this shape is covered (a white box over text is still a cover)
          if (r.alpha > 0.9) for (let i = runs.length - 1; i >= 0 && i >= runs.length - 5_000; i--) {
            const t = runs[i];
            if (t.page === page && t.order < r.order && t.box[0] >= x0 - 0.5 && t.box[2] <= x1 + 0.5 && t.box[1] >= y0 - 0.5 && t.box[3] <= y1 + 0.5 && !t.reasons.includes("covered")) t.reasons.push("covered");
          }
        }
        pathRects = []; break;
      case "n": case "S": case "s": pathRects = []; break;
      case "BDC": {
        const props = ops[ops.length - 1], tag = ops[ops.length - 2];
        let off = false;
        if (isName(tag) && tag.v === "OC") {
          const ref = isName(props) ? pdf.dict(pdf.get(resources, "Properties"))?.m[props.v] : undefined;
          off = isRef(ref) && offLayers.has(ref.n);
        }
        marked.push(off); break;
      }
      case "BMC": marked.push(false); break;
      case "EMC": marked.pop(); break;
      case "BI": { const end = content.slice(lx.p).search(/\sEI(?=[\s]|$)/); lx.p = end < 0 ? content.length : lx.p + end + 3; break; }
      case "Do": {
        const n = ops[ops.length - 1];
        if (!isName(n) || depth >= 6) break;
        const xo = pdf.dict(pdf.dict(pdf.get(resources, "XObject"))?.m[n.v]);
        if (!xo || !isName(xo.m.Subtype) || xo.m.Subtype.v !== "Form") break;
        const data = pdf.data(xo); if (data === null) break;
        const mat = pdf.resolve(xo.m.Matrix);
        const fm = Array.isArray(mat) && mat.length === 6 && mat.every((x) => typeof x === "number") ? (mat as M) : I;
        const own = pdf.dict(xo.m.Resources) ?? resources;
        // shapes in a transparency group are composited with what is under them: not counted as covering
        const group = isName(pdf.dict(xo.m.Group)?.m.S) && (pdf.dict(xo.m.Group)!.m.S as Name).v === "Transparency";
        drawPage(pdf, data, own, box, page, offLayers, runs, fills, fontCache, counter, depth + 1, { ...gs, ctm: mul(fm, gs.ctm), blend: gs.blend || group }, marked.some(Boolean));
        break;
      }
      default: break;
    }
    ops = [];
  }
}

// ---------- the document ----------

const INFO_FIELDS = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer"];
const ROUTINE_INFO = new Set(["Creator", "Producer"]);

/** join runs into lines: a new line when the baseline moves, a space when there is a gap */
function joinRuns(runs: Run[]): string {
  let out = "", prev: Run | undefined;
  for (const r of runs) {
    if (prev) {
      if (prev.page !== r.page) out += "\n\n";
      else if (Math.abs(r.y - prev.y) > Math.max(1, prev.size * 0.5)) out += "\n";
      else if (r.x - prev.endX > prev.size * 0.15 && !/\s$/.test(out) && !/^\s/.test(r.text)) out += " ";
    }
    out += r.text; prev = r;
  }
  return out.replace(/[ \t]+/g, " ").replace(/ *\n */g, "\n").trim();
}

const words = (s: string) => (s.match(/\p{L}{2,}/gu) ?? []).length;

export function extractPdf(bytes: Uint8Array): DocExtract {
  const s = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("latin1");
  const pdf = new Pdf(s);
  const segments: TextSegment[] = [];
  const findings: Finding[] = [];
  const notes: string[] = [];
  pdf.load();
  if (pdf.encrypted) {
    notes.push("the PDF is encrypted; its text was not read");
    findings.push({ pass: "channel", kind: "document.not_read", confidence: 0.3, severity: 0.5, message: "the PDF is encrypted, so its text could not be read. Unknown is not clean: open it only after decrypting it, or treat it as unread", action: "none" });
    return { format: "pdf", segments, findings, notes, complete: false };
  }
  // the page tree, from the catalog
  const catalog = [...pdf.objs.values()].find((v): v is Dict => isDict(v) && isName(v.m.Type) && v.m.Type.v === "Catalog");
  const pages: Array<{ d: Dict; res?: Dict; box: number[] }> = [];
  const seen = new Set<Dict>();
  const walk = (node: Dict | undefined, res: Dict | undefined, box: number[] | undefined, depth: number) => {
    if (!node || seen.has(node) || depth > 64 || pages.length > 10_000) return;
    seen.add(node);
    const r = pdf.dict(node.m.Resources) ?? res;
    const b = (pdf.resolve(node.m.CropBox) ?? pdf.resolve(node.m.MediaBox)) as PV;
    const bx = Array.isArray(b) && b.length === 4 && b.every((x) => typeof x === "number") ? [Math.min(b[0] as number, b[2] as number), Math.min(b[1] as number, b[3] as number), Math.max(b[0] as number, b[2] as number), Math.max(b[1] as number, b[3] as number)] : box;
    const kids = pdf.resolve(node.m.Kids);
    if (Array.isArray(kids)) for (const k of kids) walk(pdf.dict(k), r, bx, depth + 1);
    else pages.push({ d: node, res: r, box: bx ?? [0, 0, 612, 792] });
  };
  walk(pdf.dict(catalog?.m.Pages), undefined, undefined, 0);
  if (!pages.length) {
    // no catalog found (damaged file): every page object, in file order
    for (const v of pdf.objs.values()) if (isDict(v) && isName(v.m.Type) && v.m.Type.v === "Page") walk(v, undefined, undefined, 0);
  }
  if (!pages.length) notes.push("no pages were found");

  // layers switched off by default
  const offLayers = new Set<number>();
  const ocp = pdf.dict(catalog?.m.OCProperties);
  const off = pdf.resolve(pdf.dict(ocp?.m.D)?.m.OFF);
  if (Array.isArray(off)) for (const r of off) if (isRef(r)) offLayers.add(r.n);

  const fontCache = new Map<unknown, Font>();
  const counter = { order: 0, ops: 0 };
  const allRuns: Run[] = [];
  pages.forEach((pg, i) => {
    const c = pdf.resolve(pg.d.m.Contents);
    const parts = (Array.isArray(c) ? c : c ? [c] : []).map((x) => pdf.dict(x)).filter((x): x is Dict => !!x);
    const content = parts.map((p) => pdf.data(p) ?? "").join("\n");
    const runs: Run[] = [], fills: FillRect[] = [];
    drawPage(pdf, content, pg.res, pg.box, i + 1, offLayers, runs, fills, fontCache, counter);
    allRuns.push(...runs);

    // annotations and form fields: text a viewer shows only on demand, or never
    const annots = pdf.resolve(pg.d.m.Annots);
    if (Array.isArray(annots)) for (const a of annots.slice(0, 2_000)) {
      const ad = pdf.dict(a); if (!ad) continue;
      const sub = isName(ad.m.Subtype) ? ad.m.Subtype.v : "Annot";
      for (const k of ["Contents", "T", "TU", "V", "Subj", "RC"]) {
        const v = pdf.resolve(ad.m[k]);
        if (isStr(v)) { const t = pdfString(v.v).trim(); if (t.length >= 3 && !(k === "T" && words(t) < 3)) segments.push({ text: t, visibility: "comment", path: `pdf/page${i + 1}/annotation:${sub}/${k}` }); }
      }
      const act = pdf.dict(ad.m.A);
      if (act) checkAction(pdf, act, `page ${i + 1} ${sub} annotation`, findings, segments);
    }
  });

  // what is drawn: visible runs, then each kind of hidden run
  const visible = allRuns.filter((r) => !r.reasons.length);
  for (let p = 1; p <= pages.length; p++) {
    const t = joinRuns(visible.filter((r) => r.page === p));
    if (t) segments.push({ text: t, visibility: "visible", path: `pdf/page${p}/text` });
  }
  const hiddenBy = new Map<string, Run[]>();
  for (const r of allRuns) if (r.reasons.length) { const k = r.reasons[0]; hiddenBy.set(k, [...(hiddenBy.get(k) ?? []), r]); }
  for (const [reason, runs] of hiddenBy) {
    const byPage = new Map<number, Run[]>();
    for (const r of runs) byPage.set(r.page, [...(byPage.get(r.page) ?? []), r]);
    for (const [p, rs] of byPage) {
      const t = joinRuns(rs);
      if (t.replace(/\s/g, "").length < 2) continue;
      segments.push({ text: t, visibility: PDF_HIDDEN[reason].visibility, path: `pdf/page${p}/hidden:${reason}` });
    }
    const text = joinRuns(runs);
    const n = words(text);
    if (n >= 1) findings.push({ pass: "visibility", kind: "document.hidden_text", confidence: n >= 4 ? 0.3 : 0.1, severity: 0.4, message: `${n} word(s) are in the PDF's text layer but ${PDF_HIDDEN[reason].label} (page ${[...byPage.keys()].slice(0, 5).join(", ")}): an extractor reads them, a person does not see them`, excerpt: text.slice(0, 160), location: `pdf/hidden:${reason}`, inHidden: true, action: "none" });
  }

  // document information and XMP
  const infoRef = s.match(/\/Info\s+(\d+)\s+\d+\s+R/);
  const info = infoRef ? pdf.dict({ t: "ref", n: Number(infoRef[1]), g: 0 }) : undefined;
  for (const k of INFO_FIELDS) {
    const v = pdf.get(info, k);
    if (!isStr(v)) continue;
    const t = pdfString(v.v).trim();
    if (t.length < 3 || (ROUTINE_INFO.has(k) && words(t) < 8)) continue;
    segments.push({ text: t, visibility: "attribute", path: `pdf/info:${k}` });
  }
  const meta = pdf.dict(catalog?.m.Metadata);
  if (meta) { const x = pdf.data(meta); if (x) for (const t of xmpTexts(x)) if (!/xmp:CreatorTool|pdf:Producer|xmpMM:|x:xmptk|stEvt:|xmp:MetadataDate/.test(t.field) || words(t.text) >= 8) segments.push({ text: t.text, visibility: "attribute", path: `pdf/metadata:${t.field}` }); }
  const metaSaid = segments.filter((x) => /^pdf\/(?:info|metadata):/.test(x.path) && words(x.text) >= 4);
  if (metaSaid.length) findings.push({ pass: "visibility", kind: "document.metadata_text", confidence: 0.1, severity: 0.2, message: `the PDF's properties hold text nobody reading the pages sees (${metaSaid.slice(0, 4).map((x) => x.path.replace(/^pdf\//, "")).join(", ")})`, inHidden: true, action: "none" });
  const annotSaid = segments.filter((x) => x.visibility === "comment" && words(x.text) >= 4);
  if (annotSaid.length) findings.push({ pass: "visibility", kind: "document.comment_text", confidence: 0.1, severity: 0.2, message: `${annotSaid.length} annotation(s) or form field(s) carry text that is not part of the page as printed`, inHidden: true, action: "none" });

  // active content anywhere in the file
  if (catalog) {
    const oa = pdf.resolve(catalog.m.OpenAction);
    if (isDict(oa)) checkAction(pdf, oa, "opening the document", findings, segments);
    const aa = pdf.dict(catalog.m.AA);
    if (aa) for (const [k, v] of Object.entries(aa.m)) { const d = pdf.dict(v); if (d) checkAction(pdf, d, `document event ${k}`, findings, segments); }
    const names = pdf.dict(catalog.m.Names);
    if (names?.m.JavaScript !== undefined) addActive(findings, "the document carries document-level JavaScript (/Names /JavaScript): it runs in a PDF viewer, not in an agent, and its text is read like the rest", 0.3, 0.6);
    if (names?.m.EmbeddedFiles !== undefined) findings.push({ pass: "channel", kind: "document.embedded_content", confidence: 0.2, severity: 0.4, message: "the PDF carries embedded files; they were not opened or scanned. Scan them separately before anything reads them", action: "none" });
    if (pdf.resolve(pdf.dict(catalog.m.AcroForm)?.m.XFA) !== undefined) { notes.push("an XFA form is present; its XML was not read"); }
  }
  // JavaScript in any object, also outside the catalog's reach
  const jsSeen = new Set<string>();
  for (const v of pdf.objs.values()) {
    if (!isDict(v)) continue;
    const js = pdf.resolve(v.m.JS);
    if (js !== undefined) {
      const code = isStr(js) ? js.v : isDict(js) ? pdf.data(js) ?? "" : "";
      if (code && !jsSeen.has(code)) { jsSeen.add(code); segments.push({ text: code.slice(0, 20_000), visibility: "concealed", path: "pdf/javascript" }); }
    }
  }
  if (jsSeen.size && !findings.some((f) => f.kind === "document.active_content" && /JavaScript/.test(f.message))) addActive(findings, `the PDF holds ${jsSeen.size} JavaScript program(s)`, 0.3, 0.6);
  if (/\/Launch\b/.test(s) && !findings.some((f) => /launch/i.test(f.message))) addActive(findings, "the PDF names a /Launch action: opening it can ask to run a program", 0.55, 0.7);
  if (/\/RichMedia\b/.test(s)) notes.push("rich media (Flash or video) is embedded and was not read");
  notes.push(...[...new Set(pdf.notes)].slice(0, 10));
  const complete = !pdf.notes.some((n) => /not decoded|could not be decoded|stopped after/.test(n));
  return { format: "pdf", segments, findings, notes, complete, pages: pages.length };
}

function addActive(findings: Finding[], message: string, confidence: number, severity: number): void {
  findings.push({ pass: "channel", kind: "document.active_content", confidence, severity, message, action: "none" });
}

function checkAction(pdf: Pdf, act: Dict, when: string, findings: Finding[], segments: TextSegment[], depth = 0): void {
  if (depth > 8) return;
  const s = isName(act.m.S) ? act.m.S.v : "";
  if (s === "JavaScript") addActive(findings, `JavaScript runs on ${when}`, 0.35, 0.6);
  else if (s === "Launch") addActive(findings, `${when} asks to launch a program or file`, 0.6, 0.75);
  else if (s === "SubmitForm" || s === "ImportData") addActive(findings, `${when} sends or loads form data (${s})`, 0.35, 0.55);
  else if (s === "URI") {
    const u = pdf.resolve(act.m.URI);
    const url = isStr(u) ? u.v : "";
    if (/OpenAction|document event/.test(when) || when === "opening the document") addActive(findings, `${when} opens a web address${url ? ` (${url.slice(0, 80)})` : ""}`, 0.25, 0.4);
    if (url && !segments.some((x) => x.path === "pdf/link" && x.text === url)) segments.push({ text: url, visibility: "attribute", path: "pdf/link" });
  }
  const next = pdf.resolve(act.m.Next);
  for (const n of Array.isArray(next) ? next : next ? [next] : []) { const d = pdf.dict(n); if (d) checkAction(pdf, d, when, findings, segments, depth + 1); }
}

/** a PDF text string: UTF-16 with a byte order mark, UTF-8 with one, or PDFDocEncoding (close to Latin-1) */
export function pdfString(b: string): string {
  if (b.startsWith("\xfe\xff")) { let o = ""; for (let i = 2; i + 1 < b.length; i += 2) o += String.fromCharCode((b.charCodeAt(i) << 8) | b.charCodeAt(i + 1)); return o; }
  if (b.startsWith("\xff\xfe")) { let o = ""; for (let i = 2; i + 1 < b.length; i += 2) o += String.fromCharCode(b.charCodeAt(i) | (b.charCodeAt(i + 1) << 8)); return o; }
  if (b.startsWith("\xef\xbb\xbf")) return Buffer.from(b.slice(3), "latin1").toString("utf8");
  return b;
}
