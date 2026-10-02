/**
 * Text normalization for the meaning pass: produces the variants an attacker
 * uses to dodge literal matching. Each variant is scored; a hit on a variant
 * other than the original carries a small confidence discount and names the
 * transform in the finding.
 *
 * Also the decoders the character pass calls for encoded payloads.
 */

export interface Variant { name: string; text: string; discount: number }

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l", "!": "i" };

/** 1gn0r3 -> ignore, only inside tokens that mix letters and leet digits */
export function deLeet(text: string): string {
  return text.replace(/\b(?=[a-z0-9@$|!]*[a-z])(?=[a-z0-9@$|!]*[0-9@$|!])[a-z0-9@$|!]{3,}\b/gi, (w) => [...w].map((c) => LEET[c] ?? c).join(""));
}

/**
 * i.g.n.o.r.e / i-g_n.o*r:e / i g n o r e -> ignore.
 * Stage 1 folds runs of single letters joined by any non-space separators (mixed separators allowed).
 * Stage 2 folds runs joined by single spaces. Doing spaces last keeps the word break in
 * "i.g.n.o.r.e p.r.e.v" while still folding "a l l".
 */
export function deSpace(text: string): string {
  const stage1 = text.replace(/(?<![a-z])[a-z](?:[^a-z0-9\s\u00C0-\u024F][a-z]){2,}(?![a-z])/gi, (run) => run.replace(/[^a-z]/gi, ""));
  return stage1.replace(/(?<![a-z])[a-z](?: [a-z]){2,}(?![a-z])/gi, (run) => run.replace(/ /g, ""));
}

export function reverse(text: string): string {
  return [...text].reverse().join("");
}

export function rot13(text: string): string {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/** Fold the look-alike scripts that have Latin twins: Armenian, Cherokee, Lisu, Greek, Cyrillic (extended), Georgian, Latin letter-likes. */
const SKELETON: Record<string, string> = {
  // Armenian
  "օ": "o", "ո": "n", "ս": "s", "ւ": "u", "ց": "g", "հ": "h", "յ": "j", "ր": "n", "ա": "w", "զ": "q", "է": "t", "թ": "p", "լ": "l", "մ": "u", "ն": "u", "չ": "z", "ռ": "n", "ք": "p",
  "Տ": "S", "Օ": "O", "Ո": "N", "Մ": "U", "Լ": "L", "Ե": "t", "Ց": "Q",
  // Cherokee
  "Ꭰ": "D", "Ꭱ": "R", "Ꭲ": "T", "Ꭵ": "i", "Ꭺ": "A", "Ꭻ": "J", "Ꭼ": "E", "Ꮃ": "W", "Ꮇ": "M", "Ꮋ": "H", "Ꮍ": "Y", "Ꮐ": "G", "Ꮒ": "h", "Ꮓ": "Z", "Ꮟ": "b", "Ꮢ": "R", "Ꮩ": "V", "Ꮪ": "S", "Ꮮ": "L", "Ꮯ": "C", "Ꮲ": "P", "Ꮶ": "K", "Ꮼ": "J", "Ᏻ": "G", "Ᏼ": "B", "Ꭹ": "y", "Ꮅ": "O", "Ꭴ": "O", "Ꭾ": "I",
  // Lisu
  "ꓐ": "B", "ꓑ": "P", "ꓒ": "d", "ꓓ": "D", "ꓔ": "T", "ꓖ": "G", "ꓗ": "K", "ꓙ": "J", "ꓚ": "C", "ꓛ": "Z", "ꓜ": "F", "ꓝ": "M", "ꓞ": "N", "ꓟ": "L", "ꓠ": "S", "ꓡ": "R", "ꓣ": "V", "ꓤ": "H", "ꓦ": "W", "ꓧ": "X", "ꓨ": "Y", "ꓩ": "A", "ꓪ": "E", "ꓫ": "U", "ꓬ": "I", "ꓭ": "O",
  // Greek extras beyond the character pass table
  "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y",
  // Cyrillic extras
  "в": "b", "г": "r", "к": "k", "н": "h", "п": "n", "т": "t", "ч": "y", "ь": "b", "Ѳ": "o", "ӏ": "l", "ѡ": "w", "с": "c", "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "а": "a", "е": "e", "о": "o", "р": "p", "у": "y", "х": "x",
  // Coptic
  "\u2C9F": "o", "\u2C81": "a", "\u2C89": "e", "\u2C93": "i", "\u2C95": "k", "\u2C99": "m", "\u2C9B": "n", "\u2CA1": "p", "\u2CA3": "r", "\u2CA5": "s", "\u2CA7": "t", "\u2CA9": "u", "\u2CAD": "x", "\u2C8F": "z", "\u2C83": "b", "\u2C85": "g", "\u2C87": "d", "\u2C8D": "h", "\u2C97": "l", "\u2CB1": "w", "\u2CAF": "y",
  "\u2C9E": "O", "\u2C80": "A", "\u2C88": "E", "\u2C92": "I", "\u2C94": "K", "\u2C98": "M", "\u2C9A": "N", "\u2CA0": "P", "\u2CA2": "R", "\u2CA4": "S", "\u2CA6": "T", "\u2CA8": "Y", "\u2CAC": "X", "\u2C8E": "Z", "\u2C82": "B", "\u2C86": "D", "\u2C8C": "H",
  // Tifinagh
  "\u2D54": "o", "\u2D53": "u", "\u2D59": "s", "\u2D3F": "c", "\u2D4F": "i", "\u2D55": "q", "\u2D30": "a", "\u2D44": "e", "\u2D3E": "k", "\u2D4D": "l", "\u2D3B": "x", "\u2D4B": "z",
  // Canadian syllabics
  "\u1455": "c", "\u15DE": "d", "\u157C": "h", "\u148D": "j", "\u14AA": "l", "\u146D": "p", "\u15B4": "f", "\u144C": "u", "\u142F": "v", "\u15EF": "w", "\u166D": "x", "\u1431": "a", "\u15AE": "e", "\u15F7": "b", "\u1587": "r", "\u1400": "e", "\u146B": "b", "\u1401": "o", "\u1450": "o", "\u14BF": "l", "\u1468": "o", "\u15E9": "w", "\u1466": "o", "\u14EC": "n",
  // Deseret, Glagolitic, Georgian lookalikes
  "\u10432": "o", "\u10419": "O", "\u2C3B": "o", "\u2C3E": "s", "\u10FF": "o", "\u10D5": "o", "\u10E7": "y", "\u10DA": "m",
  // Latin-like symbols and letters
  "ı": "i", "ȷ": "j", "ɪ": "i", "ɴ": "n", "ʀ": "r", "ᴀ": "a", "ᴄ": "c", "ᴇ": "e", "ᴏ": "o", "ᴘ": "p", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ᴢ": "z",
  "ß": "ss", "ł": "l", "đ": "d", "ħ": "h", "ŧ": "t", "ɍ": "r", "ℓ": "l", "K": "K", "Ω": "O", "Å": "A",
};

/** NFKC fold + script skeleton + strip combining marks: the shape a human reads. */
export function skeleton(text: string): string {
  const nfkc = text.normalize("NFKC");
  let out = "";
  for (const ch of nfkc) out += SKELETON[ch] ?? ch;
  return out.normalize("NFD").replace(/\p{M}+/gu, "").normalize("NFC");
}

/** Variants of the text the meaning pass should score. The original is always first. */
export function variants(text: string): Variant[] {
  const out: Variant[] = [{ name: "original", text, discount: 1 }];
  const sk = skeleton(text);
  if (sk !== text) out.push({ name: "skeleton", text: sk, discount: 0.95 });
  const ds = deSpace(sk);
  if (ds !== sk) out.push({ name: "despaced", text: ds, discount: 0.9 });
  const dl = deLeet(ds);
  if (dl !== ds) out.push({ name: "deleet", text: dl, discount: 0.9 });
  // reversed and rot13 only matter if they contain Latin letters at all
  if (/[a-z]{4,}/i.test(sk)) {
    out.push({ name: "reversed", text: reverse(sk), discount: 0.85 });
    out.push({ name: "rot13", text: rot13(sk), discount: 0.85 });
  }
  return out;
}

// ---------- decoders ----------

const ASCII_TEXT = /^[\x09\x0A\x0D\x20-\x7E]+$/;
const looksLikeWords = (s: string) => s.length >= 12 && ASCII_TEXT.test(s) && (s.match(/[a-z]{2,}/gi) ?? []).length >= 3 && /\s/.test(s);

export interface Decoded { scheme: string; text: string; source: string }

function fromCodes(codes: number[]): string {
  let out = "";
  for (let i = 0; i < codes.length && i < 200000; i += 8192) out += String.fromCharCode(...codes.slice(i, i + 8192));
  return out;
}

export function decodePayloads(text: string): Decoded[] {
  const out: Decoded[] = [];
  const seen = new Set<string>();
  const push = (scheme: string, dec: string, source: string) => { if (looksLikeWords(dec) && !seen.has(dec)) { seen.add(dec); out.push({ scheme, text: dec, source }); } };

  // base64: contiguous runs >= 20, plus runs broken by whitespace/newlines
  for (const run of text.match(/(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])/g) ?? []) {
    try { push("base64", Buffer.from(run, "base64").toString("utf8"), run.slice(0, 60)); } catch { /* not base64 */ }
  }
  // chunk lengths are bounded (base64 lines are at most 76 chars) so a long unbroken run cannot make this quadratic
  for (const run of text.match(/(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{8,76}[ \t\r\n]{1,4}){1,40}[A-Za-z0-9+/]{4,76}={0,2}(?![A-Za-z0-9+/])/g) ?? []) {
    const joined = run.replace(/\s+/g, "");
    if (joined.length >= 24) { try { push("base64-split", Buffer.from(joined, "base64").toString("utf8"), run.slice(0, 60)); } catch { /* ignore */ } }
  }
  // base64 chunked by short line breaks (4-8 char chunks): bounded groups, bounded whitespace
  for (const run of text.match(/(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{2,76}(?:[ \t\r\n]{1,2}[A-Za-z0-9+/]{2,76}){3,400}={0,2}(?![A-Za-z0-9+/])/g) ?? []) {
    const joined = run.replace(/\s+/g, "");
    const ws = run.length - joined.length;
    if (joined.length >= 24 && ws / run.length < 0.4) { try { push("base64-chunked", Buffer.from(joined, "base64").toString("utf8"), run.slice(0, 60)); } catch { /* ignore */ } }
  }
  // quoted-printable
  for (const run of text.match(/(?:=[0-9A-F]{2}){6,}/g) ?? []) push("quoted-printable", Buffer.from(run.replace(/=/g, ""), "hex").toString("utf8"), run.slice(0, 60));
  // percent-encoding, short runs and UTF-8
  for (const run of text.match(/(?:%[0-9a-fA-F]{2}){4,}/g) ?? []) { try { push("percent", decodeURIComponent(run), run.slice(0, 60)); } catch { push("percent", Buffer.from(run.replace(/%/g, ""), "hex").toString("latin1"), run.slice(0, 60)); } }
  // base64url
  for (const run of text.match(/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])/g) ?? []) {
    if (/[_-]/.test(run)) { try { push("base64url", Buffer.from(run, "base64url").toString("utf8"), run.slice(0, 60)); } catch { /* ignore */ } }
  }
  // base32
  for (const run of text.match(/(?<![A-Z2-7])[A-Z2-7]{16,}={0,6}(?![A-Z2-7])/g) ?? []) push("base32", base32Decode(run), run.slice(0, 60));
  // hex: \x.., %.., 0x.., bare pairs
  for (const run of text.match(/(?:\\x[0-9a-fA-F]{2}){8,}|(?:%[0-9a-fA-F]{2}){8,}|(?:0x[0-9a-fA-F]{2}[\s,]*){8,}/g) ?? []) {
    const hex = run.replace(/\\x|%|0x|[\s,]/g, "");
    push("hex", Buffer.from(hex, "hex").toString("utf8"), run.slice(0, 60));
  }
  for (const run of text.match(/\b(?:[0-9a-f]{2}){12,}\b/gi) ?? []) push("hex", Buffer.from(run, "hex").toString("utf8"), run.slice(0, 60));
  // decimal / hex-pair / octal char codes: try each reading of a run of 2-3 digit tokens
  for (const run of text.match(/(?:\b[0-9a-fA-F]{2,3}[\s,;]+){8,}\b[0-9a-fA-F]{2,3}\b/g) ?? []) {
    const toks = run.split(/[\s,;]+/).filter(Boolean);
    const tryCodes = (scheme: string, parse: (t: string) => number) => {
      const codes = toks.map(parse).filter((n) => Number.isFinite(n) && n >= 9 && n < 127);
      if (codes.length >= toks.length * 0.9) push(scheme, fromCodes(codes), run.slice(0, 60));
    };
    if (toks.every((t) => /^\d+$/.test(t))) tryCodes("charcodes-decimal", (t) => parseInt(t, 10));
    if (toks.every((t) => /^[0-7]{2,3}$/.test(t))) tryCodes("charcodes-octal", (t) => parseInt(t, 8));
    if (toks.every((t) => /^[0-9a-fA-F]{2}$/.test(t))) tryCodes("charcodes-hex", (t) => parseInt(t, 16));
  }
  for (const run of text.match(/(?:[01]{8}[ \t]{0,2}){6,2000}/g) ?? []) {
    const bits = run.replace(/\s/g, "");
    let s = ""; for (let i = 0; i + 8 <= bits.length; i += 8) s += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
    push("binary", s, run.slice(0, 60));
  }
  // unicode escapes i and HTML numeric entities in non-HTML text
  if (/\\u[0-9a-f]{4}/i.test(text)) push("unicode-escape", text.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/[^\x09\x0A\x0D\x20-\x7E]/g, ""), "\\u escapes");
  // rot13 of the whole text is handled by variants(); nothing to do here
  return out;
}

function base32Decode(s: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, out = "";
  for (const c of s.replace(/=+$/, "")) {
    const idx = alphabet.indexOf(c);
    if (idx < 0) return "";
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out += String.fromCharCode((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return out;
}
