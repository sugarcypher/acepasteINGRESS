/**
 * What an image file carries besides its picture: text in metadata, data after the end of the image, extra
 * frames. Pure parsing, no dependencies, any platform. The pixels themselves are read by the vision helper
 * (image.ts); this module reads the container.
 *
 * Why it matters: a model, or the code in front of it, may be handed a file's description, comment or XMP
 * packet along with the picture. A person looking at the picture is shown none of it.
 */

import { inflateSync } from "node:zlib";

export type ImageFormat = "png" | "jpeg" | "gif" | "webp" | "bmp" | "tiff" | "heic" | "avif" | "ico" | "svg" | "pdf" | "unknown";

export interface ImageMeta {
  format: ImageFormat;
  width?: number;
  height?: number;
  /** frames or pages, when the container says (animated PNG, GIF) */
  frames?: number;
  /** text found in the container: where, and what it says */
  texts: Array<{ field: string; text: string }>;
  /** bytes after the image's own end marker */
  trailingBytes: number;
  /** what the trailing bytes look like, when they look like another file */
  trailingLooksLike?: string;
  /** an embedded preview picture (EXIF thumbnail): a second image nobody is shown */
  hasThumbnail: boolean;
  notes: string[];
}

const ascii = (b: Uint8Array, from: number, to: number) => { let s = ""; for (let i = from; i < to && i < b.length; i++) s += String.fromCharCode(b[i]); return s; };
const utf8 = (b: Uint8Array) => new TextDecoder("utf-8", { fatal: false }).decode(b);
const latin1 = (b: Uint8Array) => new TextDecoder("latin1").decode(b);
const MAX_TEXT = 20_000;

export function detectImageFormat(b: Uint8Array): ImageFormat {
  if (b.length >= 8 && b[0] === 0x89 && ascii(b, 1, 4) === "PNG") return "png";
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
  if (ascii(b, 0, 6) === "GIF87a" || ascii(b, 0, 6) === "GIF89a") return "gif";
  if (ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 12) === "WEBP") return "webp";
  if (ascii(b, 0, 2) === "BM" && b.length > 26) return "bmp";
  if (ascii(b, 0, 4) === "II*\0" || ascii(b, 0, 4) === "MM\0*") return "tiff";
  if (ascii(b, 4, 8) === "ftyp") { const brand = ascii(b, 8, 12); return /avif|avis/.test(brand) ? "avif" : /heic|heix|hevc|mif1|msf1/.test(brand) ? "heic" : "unknown"; }
  if (b.length >= 4 && b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0) return "ico";
  if (ascii(b, 0, 5) === "%PDF-") return "pdf";
  const head = utf8(b.subarray(0, 1024)).replace(/^﻿/, "").trimStart();
  if (/^(?:<\?xml[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*(?:<!DOCTYPE svg[^>]*>\s*)?<svg[\s>]/i.test(head)) return "svg";
  return "unknown";
}

/** What a run of bytes looks like, when it looks like the start of some other kind of file. */
export function looksLike(b: Uint8Array): string | undefined {
  if (b.length < 4) return undefined;
  const s = ascii(b, 0, Math.min(b.length, 64));
  if (s.startsWith("PK\x03\x04") || s.startsWith("PK\x05\x06")) return "a ZIP archive";
  if (s.startsWith("%PDF-")) return "a PDF document";
  if (s.startsWith("\x7fELF")) return "a Linux program";
  if (s.startsWith("MZ")) return "a Windows program";
  if (b[0] === 0xcf && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe) return "a macOS program";
  if (s.startsWith("#!")) return "a script";
  if (s.startsWith("Rar!")) return "a RAR archive";
  if (s.startsWith("7z\xbc\xaf")) return "a 7-Zip archive";
  if (b[0] === 0x1f && b[1] === 0x8b) return "gzip-compressed data";
  if (/^\s*<(?:!doctype html|html|script|\?php|svg)\b/i.test(s)) return "a web page or script";
  if (b[0] === 0x89 && s.slice(1, 4) === "PNG") return "another PNG image";
  if (b[0] === 0xff && b[1] === 0xd8) return "another JPEG image";
  // mostly printable: text someone appended
  let printable = 0;
  const n = Math.min(b.length, 256);
  for (let i = 0; i < n; i++) if ((b[i] >= 32 && b[i] < 127) || b[i] === 10 || b[i] === 13 || b[i] === 9) printable++;
  if (n >= 24 && printable / n > 0.9) return "text";
  return undefined;
}

const clean = (s: string) => s.replace(/\0+$/g, "").replace(/[\0-\x08\x0b\x0c\x0e-\x1f]/g, " ").trim().slice(0, MAX_TEXT);

/** XMP is XML: the values a reader might be handed are element text and attribute values. */
export function xmpTexts(xml: string): Array<{ field: string; text: string }> {
  const out: Array<{ field: string; text: string }> = [];
  const seen = new Set<string>();
  const add = (field: string, text: string) => {
    const t = clean(text.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&"));
    // identifiers, dates and numbers are not prose
    if (t.length < 12 || !/[A-Za-zÀ-￿]{3,}\s+[A-Za-zÀ-￿]{2,}/.test(t) || seen.has(t)) return;
    seen.add(t); out.push({ field: `xmp:${field}`, text: t });
  };
  for (const m of xml.slice(0, 2_000_000).matchAll(/<([A-Za-z][\w.-]*:[\w.-]+)[^>]*>([^<]{12,})<\/\1>/g)) add(m[1], m[2]);
  for (const m of xml.slice(0, 2_000_000).matchAll(/<rdf:li[^>]*>([^<]{12,})<\/rdf:li>/g)) add("li", m[1]);
  for (const m of xml.slice(0, 2_000_000).matchAll(/\s([A-Za-z][\w.-]*:[\w.-]+)="([^"]{12,})"/g)) if (!/^xmlns:|^rdf:about$|^xml:/.test(m[1])) add(m[1], m[2]);
  return out.slice(0, 60);
}

// ---------- EXIF (a TIFF structure) ----------

const EXIF_TEXT_TAGS: Record<number, string> = {
  0x010e: "ImageDescription", 0x010f: "Make", 0x0110: "Model", 0x0131: "Software", 0x013b: "Artist", 0x8298: "Copyright",
  0x9286: "UserComment", 0x9c9b: "XPTitle", 0x9c9c: "XPComment", 0x9c9d: "XPAuthor", 0x9c9e: "XPKeywords", 0x9c9f: "XPSubject",
  0x02bc: "XMP", 0x83bb: "IPTC", 0xa420: "ImageUniqueID", 0xc4a5: "PrintIM",
};

function exifTexts(t: Uint8Array): { texts: Array<{ field: string; text: string }>; hasThumbnail: boolean } {
  const texts: Array<{ field: string; text: string }> = [];
  let hasThumbnail = false;
  if (t.length < 8) return { texts, hasThumbnail };
  const le = ascii(t, 0, 2) === "II";
  if (!le && ascii(t, 0, 2) !== "MM") return { texts, hasThumbnail };
  const dv = new DataView(t.buffer, t.byteOffset, t.byteLength);
  const u16 = (o: number) => (o + 2 <= t.length ? dv.getUint16(o, le) : 0);
  const u32 = (o: number) => (o + 4 <= t.length ? dv.getUint32(o, le) : 0);
  const visited = new Set<number>();
  const walk = (ifd: number, depth: number, index: number) => {
    if (!ifd || ifd + 2 > t.length || visited.has(ifd) || depth > 4 || visited.size > 16) return;
    visited.add(ifd);
    const n = Math.min(u16(ifd), 400);
    for (let i = 0; i < n; i++) {
      const e = ifd + 2 + i * 12;
      if (e + 12 > t.length) break;
      const tag = u16(e), type = u16(e + 2), count = u32(e + 4);
      const size = ({ 1: 1, 2: 1, 7: 1, 3: 2, 4: 4 } as Record<number, number>)[type];
      if (tag === 0x8769 || tag === 0xa005 || tag === 0x8825) { if (tag !== 0x8825) walk(u32(e + 8), depth + 1, index); continue; }
      if (tag === 0x0201 && index === 1) hasThumbnail = true; // JPEGInterchangeFormat in the second directory
      const name = EXIF_TEXT_TAGS[tag];
      if (!name || !size || count === 0 || count > 2_000_000) continue;
      const bytes = count * size;
      const at = bytes <= 4 ? e + 8 : u32(e + 8);
      if (at + bytes > t.length) continue;
      const raw = t.subarray(at, at + bytes);
      let text: string;
      if (name === "XMP") { texts.push(...xmpTexts(utf8(raw))); continue; }
      if (name.startsWith("XP")) text = new TextDecoder("utf-16le").decode(raw);
      else if (name === "UserComment") {
        const code = ascii(raw, 0, 8);
        text = code.startsWith("UNICODE") ? new TextDecoder(le ? "utf-16le" : "utf-16be").decode(raw.subarray(8)) : utf8(raw.subarray(code.startsWith("ASCII") || code.startsWith("JIS") || /^\0{8}$/.test(code) ? 8 : 0));
      } else if (type === 2) text = utf8(raw);
      else continue;
      text = clean(text);
      if (text.length >= 3) texts.push({ field: `exif:${name}`, text });
    }
    const next = u32(ifd + 2 + n * 12);
    if (next) walk(next, depth, index + 1);
  };
  walk(u32(4), 0, 0);
  return { texts, hasThumbnail };
}

// ---------- containers ----------

function parsePng(b: Uint8Array, m: ImageMeta): void {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 8, end = -1, chunks = 0;
  while (o + 12 <= b.length && chunks++ < 100_000) {
    const len = dv.getUint32(o), type = ascii(b, o + 4, o + 8);
    const data = b.subarray(o + 8, Math.min(b.length, o + 8 + len));
    if (type === "IHDR" && len >= 8) { m.width = dv.getUint32(o + 8); m.height = dv.getUint32(o + 12); }
    else if (type === "acTL" && len >= 4) m.frames = dv.getUint32(o + 8);
    else if (type === "tEXt") {
      const z = data.indexOf(0);
      if (z > 0) m.texts.push({ field: `png:${clean(latin1(data.subarray(0, z))).slice(0, 80)}`, text: clean(latin1(data.subarray(z + 1))) });
    } else if (type === "zTXt") {
      const z = data.indexOf(0);
      if (z > 0 && z + 2 <= data.length) { try { m.texts.push({ field: `png:${clean(latin1(data.subarray(0, z))).slice(0, 80)}`, text: clean(latin1(inflateSync(data.subarray(z + 2), { maxOutputLength: 4_000_000 }))) }); } catch { m.notes.push("a compressed text chunk could not be read"); } }
    } else if (type === "iTXt") {
      const z = data.indexOf(0);
      if (z > 0 && z + 3 <= data.length) {
        const key = clean(latin1(data.subarray(0, z))).slice(0, 80);
        const compressed = data[z + 1] === 1;
        let p = z + 3;
        p = data.indexOf(0, p) + 1; // language tag
        if (p > 0) { const q = data.indexOf(0, p); p = q >= 0 ? q + 1 : -1; } // translated keyword
        if (p > 0) {
          try {
            const body = compressed ? inflateSync(data.subarray(p), { maxOutputLength: 4_000_000 }) : data.subarray(p);
            const text = utf8(body);
            if (/XML:com\.adobe\.xmp/i.test(key) || /<x:xmpmeta|<rdf:RDF/.test(text.slice(0, 400))) m.texts.push(...xmpTexts(text));
            else m.texts.push({ field: `png:${key}`, text: clean(text) });
          } catch { m.notes.push("a compressed text chunk could not be read"); }
        }
      }
    } else if (type === "eXIf") { const e = exifTexts(data); m.texts.push(...e.texts); m.hasThumbnail ||= e.hasThumbnail; }
    o += 12 + len;
    if (type === "IEND") { end = o; break; }
  }
  if (end < 0) m.notes.push("the PNG has no end marker");
  else setTrailing(b, end, m);
}

function parseJpeg(b: Uint8Array, m: ImageMeta): void {
  let o = 2, end = -1, guard = 0;
  while (o + 4 <= b.length && guard++ < 100_000) {
    if (b[o] !== 0xff) { o++; continue; }
    const marker = b[o + 1];
    if (marker === 0xff) { o++; continue; }
    if (marker === 0xd9) { end = o + 2; break; }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) { o += 2; continue; }
    const len = (b[o + 2] << 8) | b[o + 3];
    if (len < 2) break;
    const data = b.subarray(o + 4, Math.min(b.length, o + 2 + len));
    if (marker === 0xfe) { const t = clean(utf8(data)); if (t.length >= 3) m.texts.push({ field: "jpeg:comment", text: t }); }
    else if (marker === 0xe1 && ascii(data, 0, 6) === "Exif\0\0") { const e = exifTexts(data.subarray(6)); m.texts.push(...e.texts); m.hasThumbnail ||= e.hasThumbnail; }
    else if (marker === 0xe1 && ascii(data, 0, 28) === "http://ns.adobe.com/xap/1.0/") m.texts.push(...xmpTexts(utf8(data.subarray(29))));
    else if (marker === 0xed) { // Photoshop / IPTC: caption and keywords are plain strings inside
      for (const t of utf8(data).match(/[\x20-\x7e -￿]{16,}/g) ?? []) if (/[A-Za-z]{3,}\s+[A-Za-z]{2,}\s+[A-Za-z]{2,}/.test(t) && !/^Photoshop 3\.0/.test(t)) m.texts.push({ field: "iptc", text: clean(t) });
    }
    else if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker) && data.length >= 5) { m.height = (data[1] << 8) | data[2]; m.width = (data[3] << 8) | data[4]; }
    if (marker === 0xda) {
      // entropy-coded data runs to the next real marker
      let p = o + 2 + len;
      while (p + 1 < b.length) {
        if (b[p] === 0xff && b[p + 1] !== 0 && !(b[p + 1] >= 0xd0 && b[p + 1] <= 0xd7) && b[p + 1] !== 0xff) break;
        p++;
      }
      o = p; continue;
    }
    o += 2 + len;
  }
  if (end < 0) m.notes.push("the JPEG has no end marker");
  else setTrailing(b, end, m);
}

function parseGif(b: Uint8Array, m: ImageMeta): void {
  if (b.length < 13) return;
  m.width = b[6] | (b[7] << 8); m.height = b[8] | (b[9] << 8);
  let o = 13 + (b[10] & 0x80 ? 3 * (1 << ((b[10] & 7) + 1)) : 0);
  let frames = 0, end = -1, guard = 0;
  const skipBlocks = (p: number) => { while (p < b.length && b[p] !== 0) p += b[p] + 1; return p + 1; };
  while (o < b.length && guard++ < 1_000_000) {
    const c = b[o];
    if (c === 0x3b) { end = o + 1; break; }
    if (c === 0x2c) { frames++; const flags = b[o + 9] ?? 0; o += 10 + (flags & 0x80 ? 3 * (1 << ((flags & 7) + 1)) : 0) + 1; o = skipBlocks(o); continue; }
    if (c === 0x21) {
      const label = b[o + 1];
      let p = o + 2;
      if (label === 0xfe) {
        const parts: Uint8Array[] = [];
        while (p < b.length && b[p] !== 0) { parts.push(b.subarray(p + 1, p + 1 + b[p])); p += b[p] + 1; }
        const t = clean(utf8(Buffer.concat(parts)));
        if (t.length >= 3) m.texts.push({ field: "gif:comment", text: t });
        o = p + 1; continue;
      }
      if (label === 0xff && ascii(b, o + 3, o + 14) === "XMP DataXMP") {
        const start = o + 14; let q = start;
        while (q < b.length && !(b[q] === 0x01 && b[q + 1] === 0xff && b[q + 2] === 0xfe)) q++;
        m.texts.push(...xmpTexts(utf8(b.subarray(start, q))));
      }
      o = skipBlocks(p); continue;
    }
    break;
  }
  m.frames = frames || undefined;
  if (end >= 0) setTrailing(b, end, m);
}

function parseWebp(b: Uint8Array, m: ImageMeta): void {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const riffEnd = Math.min(b.length, 8 + dv.getUint32(4, true));
  let o = 12, frames = 0, guard = 0;
  while (o + 8 <= riffEnd && guard++ < 100_000) {
    const type = ascii(b, o, o + 4), len = dv.getUint32(o + 4, true);
    const data = b.subarray(o + 8, Math.min(riffEnd, o + 8 + len));
    if (type === "EXIF") { const e = exifTexts(ascii(data, 0, 6) === "Exif\0\0" ? data.subarray(6) : data); m.texts.push(...e.texts); m.hasThumbnail ||= e.hasThumbnail; }
    else if (type === "XMP ") m.texts.push(...xmpTexts(utf8(data)));
    else if (type === "ANMF") frames++;
    else if (type === "VP8X" && data.length >= 10) { m.width = 1 + (data[4] | (data[5] << 8) | (data[6] << 16)); m.height = 1 + (data[7] | (data[8] << 8) | (data[9] << 16)); }
    o += 8 + len + (len & 1);
  }
  if (frames) m.frames = frames;
  setTrailing(b, riffEnd + (riffEnd & 1 && riffEnd < b.length ? 1 : 0), m);
}

function setTrailing(b: Uint8Array, end: number, m: ImageMeta): void {
  // a few bytes of padding or a newline after the end marker are common and mean nothing
  let from = end;
  while (from < b.length && (b[from] === 0 || b[from] === 0x0a || b[from] === 0x0d || b[from] === 0x20)) from++;
  m.trailingBytes = b.length - from;
  if (m.trailingBytes >= 4) m.trailingLooksLike = looksLike(b.subarray(from));
}

/** Read an image file's container. Never throws: a file that cannot be parsed is reported as such. */
export function readImageMeta(bytes: Uint8Array): ImageMeta {
  const m: ImageMeta = { format: detectImageFormat(bytes), texts: [], trailingBytes: 0, hasThumbnail: false, notes: [] };
  try {
    switch (m.format) {
      case "png": parsePng(bytes, m); break;
      case "jpeg": parseJpeg(bytes, m); break;
      case "gif": parseGif(bytes, m); break;
      case "webp": parseWebp(bytes, m); break;
      case "tiff": { const e = exifTexts(bytes); m.texts.push(...e.texts); m.notes.push("TIFF: data after the image is not measured"); break; }
      case "heic": case "avif": case "bmp": case "ico": m.notes.push(`${m.format.toUpperCase()}: metadata inside the file is not read`); break;
      default: break;
    }
  } catch (e) {
    m.notes.push(`the file's structure could not be read to the end (${(e as Error).message?.slice(0, 80) ?? "error"})`);
  }
  // drop empty and duplicate texts, cap the count
  const seen = new Set<string>();
  m.texts = m.texts.filter((t) => t.text.length >= 3 && !seen.has(t.text) && seen.add(t.text)).slice(0, 80);
  return m;
}
