/**
 * Character pass (AcePaste lineage).
 *
 * The hostile-invisible alphabet is ported verbatim from the production
 * AcePaste cleaner (see acepaste-alphabet.ts), so the gate strips exactly
 * what the web tool and the Chrome extension strip. On top of that shared
 * set, the gate adds script-aware exceptions: zero-width joiners inside
 * emoji sequences and Indic/Arabic text, zero-width non-joiners in complex
 * scripts, and bidirectional marks (not overrides or isolates) inside
 * right-to-left runs are legitimate and left in place; and it adds the
 * decode-and-rescan behavior the gate needs that the cleaner does not.
 */

import type { Finding } from "./types.js";
import { decodePayloads } from "./normalize.js";
import { countHostileInvisibles } from "./acepaste-alphabet.js";
export { countHostileInvisibles } from "./acepaste-alphabet.js";

export interface CharacterResult {
  /** text with hostile characters removed and encoded payloads untouched */
  cleaned: string;
  findings: Finding[];
  /** decoded payloads that should be rescanned by the meaning pass */
  decodedPayloads: string[];
}

const TAG_RANGE = /[\u{E0000}-\u{E007F}]/gu;
// AcePaste basic-plane invisibles minus the code points with dedicated handling below
// (ZWJ/ZWNJ script-aware, LRM/RLM bidi-mark-aware, bidi overrides, variation selectors).
const ZERO_WIDTH = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B\u2060-\u206F\u2800\u3164\uFEFF\uFFA0]/g;
const ZWJ = "‍";
const ZWNJ = "‌";
const BIDI_OVERRIDE_ISOLATE = /[‪-‮⁦-⁩]/g; // embeddings, overrides, isolates: never legitimate in plain text intake
const BIDI_MARKS = /[‎‏؜]/g; // LRM, RLM, ALM: legitimate in RTL text
const VARIATION_SELECTORS = /[︀-️]|[\u{E0100}-\u{E01EF}]/gu;

const EMOJI_ADJ = /\p{Extended_Pictographic}|[\u{1F3FB}-\u{1F3FF}]|️/u;
const INDIC_OR_ARABIC = /[؀-ۿݐ-ݿࢠ-ࣿऀ-෿က-႟ក-៿]/u;
const RTL_SCRIPT = /[֐-׿؀-ۿݐ-ݿࢠ-ࣿיִ-﷿ﹰ-﻿]/u;

// Minimal confusable table: Cyrillic/Greek letters that render like Latin.
const CONFUSABLE: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ѕ": "s",
  "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
  "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
  "Р": "P", "С": "C", "Т": "T", "Х": "X",
};

function excerptAround(text: string, idx: number, span = 40): string {
  return text.slice(Math.max(0, idx - span), idx + span).replace(/[\p{Cf}\p{Mn}]/gu, "�");
}

export function scanCharacters(text: string): CharacterResult {
  const findings: Finding[] = [];
  const decodedPayloads: string[] = [];
  let cleaned = text;

  // 0. Lone surrogates: never legitimate; replace so downstream re-encoding cannot mangle them
  const lone = cleaned.match(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g);
  if (lone) cleaned = cleaned.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\uFFFD");

  // 1. Unicode tag characters: the flagship vector. Decode what they spell.
  const tags = [...text.matchAll(TAG_RANGE)];
  if (tags.length) {
    const spelled = tags
      .map((m) => {
        const cp = m[0].codePointAt(0)!;
        return cp >= 0xe0020 && cp <= 0xe007e ? String.fromCodePoint(cp - 0xe0000) : "";
      })
      .join("");
    findings.push({
      pass: "character",
      kind: "unicode.tag_characters",
      confidence: 0.98,
      severity: 0.95,
      message: `${tags.length} Unicode Plane 14 tag characters spelling hidden ASCII`,
      excerpt: spelled.slice(0, 200),
      location: `offset ${tags[0].index}`,
      action: "neutralized",
    });
    if (spelled.trim()) decodedPayloads.push(spelled);
    cleaned = cleaned.replace(TAG_RANGE, "");
  }

  // 2. Bidirectional overrides and isolates: never legitimate here.
  const bidi = [...cleaned.matchAll(BIDI_OVERRIDE_ISOLATE)];
  if (bidi.length) {
    findings.push({
      pass: "character",
      kind: "unicode.bidi_control",
      confidence: 0.9,
      severity: 0.7,
      message: `${bidi.length} bidirectional override/isolate controls (Trojan Source class)`,
      excerpt: excerptAround(cleaned, bidi[0].index!),
      location: `offset ${bidi[0].index}`,
      action: "neutralized",
    });
    cleaned = cleaned.replace(BIDI_OVERRIDE_ISOLATE, "");
  }
  // bidi marks outside any right-to-left run are suspicious; inside one they are normal
  const marks = [...cleaned.matchAll(BIDI_MARKS)];
  const strayMarks = marks.filter((m) => !RTL_SCRIPT.test(cleaned.slice(Math.max(0, m.index! - 24), m.index! + 24)));
  if (strayMarks.length >= 3) {
    findings.push({
      pass: "character",
      kind: "unicode.bidi_control",
      confidence: 0.6,
      severity: 0.4,
      message: `${strayMarks.length} bidirectional marks outside any right-to-left text`,
      location: `offset ${strayMarks[0].index}`,
      action: "neutralized",
    });
    for (const m of strayMarks.reverse()) cleaned = cleaned.slice(0, m.index) + cleaned.slice(m.index! + 1);
  }

  // 3. Zero-width characters, script-aware.
  const zw = [...cleaned.matchAll(ZERO_WIDTH)];
  const joinerStray: number[] = [];
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (ch !== ZWJ && ch !== ZWNJ) continue;
    const prev = cleaned.slice(Math.max(0, i - 2), i);
    const next = cleaned.slice(i + 1, i + 3);
    const emojiCtx = ch === ZWJ && (EMOJI_ADJ.test(prev) || EMOJI_ADJ.test(next));
    const complexScriptCtx = INDIC_OR_ARABIC.test(prev) || INDIC_OR_ARABIC.test(next);
    if (!emojiCtx && !complexScriptCtx) joinerStray.push(i);
  }
  const total = zw.length + joinerStray.length;
  if (total > 0) {
    // density matters: a couple is a copy-paste artifact; dozens is a channel
    const density = total / Math.max(1, cleaned.length);
    const confidence = Math.min(0.97, 0.35 + Math.min(total, 40) / 50 + density * 50);
    findings.push({
      pass: "character",
      kind: "unicode.zero_width",
      confidence,
      severity: total >= 8 ? 0.8 : 0.3,
      message: `${total} zero-width characters outside emoji or complex-script context`,
      excerpt: excerptAround(cleaned, zw[0]?.index ?? joinerStray[0]),
      location: `offset ${zw[0]?.index ?? joinerStray[0]}`,
      action: "neutralized",
    });
    // decode binary-channel smuggling (ZWSP/ZWNJ as bits) when dense
    if (total >= 16) {
      const bits = [...cleaned].filter((c) => c === "​" || c === "‌").map((c) => (c === "​" ? "0" : "1")).join("");
      if (bits.length >= 16) {
        let out = "";
        for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
        if (/^[\x20-\x7E\s]+$/.test(out)) decodedPayloads.push(out);
      }
    }
    // single pass removal: indices in joinerStray refer to the string before any removal
    const drop = new Set(joinerStray);
    let out = "";
    for (let i = 0; i < cleaned.length; i++) {
      const ch = cleaned[i];
      if (drop.has(i)) continue;
      if (/[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B\u2060-\u206F\u2800\u3164\uFEFF\uFFA0]/.test(ch)) continue;
      out += ch;
    }
    cleaned = out;
  }

  // 3b. Whitespace channels (AcePaste FORMATTING_RE lineage). Unicode has a dozen spaces that render identically
  //     (en, em, thin, hair, figure, punctuation, narrow no-break, medium mathematical, ideographic) plus line and
  //     paragraph separators. One or two are typography; many, interleaved with ordinary spaces in Latin text, are a
  //     channel: the choice of space at each word gap carries a bit, which no human reader can see.
  {
    const ODD = /[\u2000-\u200A\u2028\u2029\u202F\u205F]/g;
    // only look-alike spaces in a word gap count; typography is excluded: French spacing before ; : ! ? and inside « »,
    // thousands separators between digits, and indentation (a space next to a line break or another space)
    const odd = [...cleaned.matchAll(ODD)].filter((m) => {
      const i = m.index!, prev = cleaned[i - 1] ?? "", next = cleaned[i + 1] ?? "";
      if (!prev || !next || /\s/.test(prev) || /\s/.test(next)) return false;
      if (/[;:!?»%€]/.test(next) || prev === "«") return false;
      if (/\d/.test(prev) && /\d/.test(next)) return false;
      return true;
    });
    const cjk = /[\u3040-\u30FF\u3400-\u9FFF\uAC00-\uD7AF]/.test(cleaned);
    const ideographic = cjk ? 0 : (cleaned.match(/\u3000/g) ?? []).length;
    const n = odd.length + ideographic;
    const kinds = new Set([...odd.map((m) => m[0]), ...(ideographic ? ["\u3000"] : [])]);
    const asciiGaps = (cleaned.match(/(?<=\S) (?=\S)/g) ?? []).length;
    if (n >= 8 && (kinds.size >= 2 || asciiGaps >= 4)) {
      findings.push({
        pass: "character", kind: "unicode.whitespace_channel",
        confidence: Math.min(0.95, 0.5 + n / 60), severity: n >= 16 ? 0.75 : 0.45,
        message: `${n} look-alike Unicode spaces (${kinds.size} kinds) mixed into ordinary word gaps: the choice of space can carry hidden bits`,
        excerpt: excerptAround(cleaned, odd[0]?.index ?? 0), location: `offset ${odd[0]?.index ?? 0}`, action: "neutralized",
      });
      // decode: every word gap is a bit (ordinary space = 0, any look-alike = 1), read as 8-bit ASCII
      const gaps = [...cleaned.matchAll(/(?<=\S)([ \u2000-\u200A\u202F\u205F\u3000])(?=\S)/g)].map((m) => (m[1] === " " ? "0" : "1")).join("");
      for (const bits of [gaps, gaps.replace(/[01]/g, (b) => (b === "0" ? "1" : "0"))]) {
        let out = "";
        for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
        if (out.length >= 4 && /^[\x20-\x7E]+$/.test(out) && /[a-z]{3}/i.test(out)) { decodedPayloads.push(out); break; }
      }
      cleaned = cleaned.replace(ODD, " ").replace(cjk ? /$^/ : /\u3000/g, " ");
    }
  }

  // 4. Variation-selector smuggling: runs of selectors not attached to a base that takes them.
  const vsRuns = [...cleaned.matchAll(/(?:[︀-️]|[\u{E0100}-\u{E01EF}]){4,}/gu)];
  if (vsRuns.length) {
    const n = vsRuns.reduce((a, m) => a + [...m[0]].length, 0);
    const bytes = vsRuns.flatMap((m) => [...m[0]].map((c) => {
      const cp = c.codePointAt(0)!;
      return cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16;
    }));
    const decoded = bytes.filter((b) => b >= 0x20 && b < 0x7f).slice(0, 100000).map((b) => String.fromCharCode(b)).join("");
    findings.push({
      pass: "character",
      kind: "unicode.variation_selector_smuggling",
      confidence: 0.92,
      severity: 0.9,
      message: `${n} chained variation selectors encoding ${bytes.length} bytes`,
      excerpt: decoded.slice(0, 120),
      location: `offset ${vsRuns[0].index}`,
      action: "neutralized",
    });
    if (decoded.trim()) decodedPayloads.push(decoded);
    cleaned = cleaned.replace(/(?:[︀-️]|[\u{E0100}-\u{E01EF}]){4,}/gu, "");
  }

  // 5. Mixed-script words: Latin letters sharing a word with letters of another script. Legitimate text does this rarely
  //    (brand names, transliteration glosses); injection spelled with look-alikes does it in every keyword.
  const words = cleaned.match(/[\p{L}\p{M}]{3,}/gu) ?? [];
  let confusableWords = 0;
  let sample = "";
  for (const w of words) {
    const hasLatin = /\p{Script=Latin}/u.test(w);
    if (!hasLatin) continue;
    const hasOther = /[^\p{Script=Latin}\p{Script=Common}\p{Script=Inherited}]/u.test(w);
    if (hasOther) { confusableWords++; if (!sample) sample = w; }
  }
  if (confusableWords > 0) {
    findings.push({
      pass: "character",
      kind: "unicode.mixed_script_confusable",
      confidence: Math.min(0.9, 0.4 + confusableWords * 0.1),
      severity: 0.5,
      message: `${confusableWords} words mixing Latin with look-alike Cyrillic/Greek letters`,
      excerpt: sample,
      action: "neutralized",
    });
    cleaned = cleaned.replace(/[\p{L}\p{M}]{3,}/gu, (w) =>
      /\p{Script=Latin}/u.test(w) ? [...w].map((c) => CONFUSABLE[c] ?? c).join("") : w,
    );
  }

  // 5b. Full-width and mathematical alphanumeric look-alikes: ｉｇｎｏｒｅ, 𝗶𝗴𝗻𝗼𝗿𝗲. Humans read them fine; tokenizers and keyword filters do not.
  const fwRuns = cleaned.match(/[\uFF21-\uFF3A\uFF41-\uFF5A]{3,}|[\u{1D400}-\u{1D7FF}]{3,}|[\u24B6-\u24E9\u{1F130}-\u{1F189}]{3,}/gu) ?? [];
  if (fwRuns.length) {
    const folded = (t: string) => t.normalize("NFKC");
    findings.push({
      pass: "character", kind: "unicode.fullwidth_or_math_lookalike",
      confidence: Math.min(0.85, 0.35 + fwRuns.length * 0.1), severity: 0.5,
      message: `${fwRuns.length} runs of full-width, mathematical or enclosed letters standing in for Latin`,
      excerpt: fwRuns.slice(0, 3).map(folded).join(" "), action: "neutralized",
    });
    cleaned = cleaned.replace(/[\uFF21-\uFF3A\uFF41-\uFF5A]+|[\u{1D400}-\u{1D7FF}]+|[\u24B6-\u24E9\u{1F130}-\u{1F189}]+/gu, (r) => r.normalize("NFKC"));
  }

  // 5c. Combining-mark floods (zalgo): more than 4 combining marks on one base is never legitimate text
  const floods = cleaned.match(/[\p{M}]{5,}/gu) ?? [];
  if (floods.length) {
    findings.push({
      pass: "character", kind: "unicode.combining_flood",
      confidence: Math.min(0.9, 0.5 + floods.length * 0.1), severity: 0.4,
      message: `${floods.length} combining-mark floods (${Math.max(...floods.map((f) => [...f].length))} marks on one base)`,
      action: "neutralized",
    });
    cleaned = cleaned.replace(/([^\p{M}])[\p{M}]{5,}/gu, "$1");
  }

  // 6. Encoded payloads: base64 (incl. short and whitespace-split), base64url, base32, hex, char codes, binary, \u escapes.
  const decoded = decodePayloads(cleaned);
  for (const d of decoded) decodedPayloads.push(d.text);
  if (decoded.length) {
    findings.push({
      pass: "character",
      kind: "unicode.encoded_payload",
      confidence: 0.5,
      severity: 0.4,
      message: `${decoded.length} encoded blobs (${[...new Set(decoded.map((d) => d.scheme))].join(", ")}) decoded to readable text; rescanned by meaning pass`,
      excerpt: decoded[0].text.slice(0, 120),
      action: "none",
    });
  }

  return { cleaned, findings, decodedPayloads };
}
